import { DEFAULT_CONNECTION_CONFIG } from '../src/Defaults'
import { makeUSyncSocket } from '../src/Socket/usync'
import { USyncQuery, USyncUser } from '../src/WAUSync'
import { authState } from './auth'
import { authorized, contactResult, phoneFrom, reply, route } from './http'

interface Env { API_KEY: string; ADMIN_KEY: string; SESSION: DurableObjectNamespace }
const silent = { level: 'silent', child() { return this }, trace() {}, debug() {}, info() {}, warn() {}, error() {} }

export default {
  async fetch(request: Request, env: Env) {
    const path = new URL(request.url).pathname
    if (path === '/pair' || path === '/session') {
      if (!await authorized(request, env.ADMIN_KEY)) return reply({ error: 'unauthorized' }, 401)
    } else {
      if (path !== '/check') return reply({ error: 'not_found' }, 404)
      if (!await authorized(request, env.API_KEY)) return reply({ error: 'unauthorized' }, 401)
    }
    return env.SESSION.get(env.SESSION.idFromName('single-account')).fetch(request)
  }
}

export class WhatsAppSession {
  private socket?: ReturnType<typeof makeUSyncSocket>
  private auth?: Awaited<ReturnType<typeof authState>>
  private status: 'closed' | 'connecting' | 'pairing' | 'open' = 'closed'
  private starting?: Promise<void>
  private writing: Promise<void> = Promise.resolve()
  private storageFailed = false
  private busy = false

  constructor(private ctx: DurableObjectState, private env: Env) {}

  private async connect(pair = false) {
    if (this.storageFailed) throw new Error('Storage unavailable')
    if (this.status === 'open' || this.status === 'pairing') return
    if (this.starting) return this.starting
    this.starting = this.start(pair).finally(() => { this.starting = undefined })
    return this.starting
  }

  private async start(pair: boolean) {
    await this.writing
    this.auth ??= await authState(this.ctx.storage)
    if (!pair && !this.auth.state.creds.me) throw new Error('Pairing required')
    this.status = 'connecting'
    const socket = makeUSyncSocket({
      ...DEFAULT_CONNECTION_CONFIG,
      auth: this.auth.state,
      logger: silent,
      connectTimeoutMs: 15_000,
      defaultQueryTimeoutMs: 10_000,
      markOnlineOnConnect: false,
      fireInitQueries: false,
      syncFullHistory: false,
      shouldSyncHistoryMessage: () => false,
      shouldIgnoreJid: () => true
    })
    this.socket = socket
    socket.ev.on('creds.update', update => {
      Object.assign(this.auth!.state.creds, update)
      this.writing = this.writing.then(() => this.auth!.saveCreds()).catch(() => {
        this.storageFailed = true
        socket.end(new Error('Storage unavailable'))
      })
      this.ctx.waitUntil(this.writing)
    })
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.end(new Error('Connection timeout'))
        reject(new Error('Connection timeout'))
      }, 15_000)
      socket.ev.on('connection.update', update => {
        if (socket !== this.socket) return
        if (update.qr) {
          this.status = 'pairing'
          clearTimeout(timer)
          resolve()
        }
        if (update.connection === 'open') {
          this.status = 'open'
          clearTimeout(timer)
          resolve()
        }
        if (update.connection === 'close') {
          this.status = 'closed'
          this.socket = undefined
          clearTimeout(timer)
          reject(new Error('Connection closed'))
        }
      })
    })
  }

  async fetch(request: Request) {
    const path = new URL(request.url).pathname
    const secret = path === '/check' ? this.env.API_KEY : this.env.ADMIN_KEY
    if (!await authorized(request, secret)) return reply({ error: 'unauthorized' }, 401)
    if (this.busy) return reply({ error: 'busy' }, 429)
    this.busy = true
    try {
      if (path === '/pair' && request.method === 'POST') {
        const phone = phoneFrom(request)
        if (!phone) return reply({ error: 'invalid_phone' }, 400)
        await this.connect(true)
        if (this.auth!.state.creds.me) return reply({ error: 'already_paired' }, 409)
        const code = await this.socket!.requestPairingCode(phone)
        await this.writing
        if (this.storageFailed) throw new Error('Storage unavailable')
        return reply({ code })
      }
      if (path === '/session' && request.method === 'GET') {
        await this.connect()
        return reply({ connected: this.status === 'open' })
      }
      return await route(request, this.env.API_KEY, async phone => {
        await this.connect()
        if (this.status !== 'open') throw new Error('Pairing required')
        const result = await this.socket!.executeUSyncQuery(new USyncQuery()
          .withContactProtocol().withUser(new USyncUser().withPhone(`+${phone}`)))
        await this.writing
        if (this.storageFailed) throw new Error('Storage unavailable')
        return contactResult(result)
      })
    } catch {
      return reply({ error: 'whatsapp_unavailable' }, 503)
    } finally { this.busy = false }
  }
}
