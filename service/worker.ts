import { DEFAULT_CONNECTION_CONFIG } from '../src/Defaults'
import { makeUSyncSocket } from '../src/Socket/usync'
import { USyncQuery, USyncUser } from '../src/WAUSync'
import { authState } from './auth'
import { authorized, contactResult, phoneFrom, reply, route } from './http'

interface Env { API_KEY: string; ADMIN_KEY: string; SESSION_KEY: string; ENABLE_PAIRING?: string; SESSION: DurableObjectNamespace }
const silent = { level: 'silent', child() { return this }, trace() {}, debug() {}, info() {}, warn() {}, error() {} }

export default {
  async fetch(request: Request, env: Env) {
    const path = new URL(request.url).pathname
    if (env.API_KEY === env.ADMIN_KEY) return reply({ error: 'configuration_error' }, 503)
    if (path === '/pair' || path === '/session') {
      if (!await authorized(request, env.ADMIN_KEY)) return reply({ error: 'unauthorized' }, 401)
    } else {
      if (path !== '/check') return reply({ error: 'not_found' }, 404)
      if (!await authorized(request, env.API_KEY)) return reply({ error: 'unauthorized' }, 401)
    }
    return env.SESSION.get(env.SESSION.idFromName('single-account')).fetch(request)
  }
}

const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
const disconnectCode = (error: unknown): number | undefined =>
  (error as { output?: { statusCode?: number } })?.output?.statusCode
const temporary = (error: unknown) => [408, 428, 503, 515].includes(disconnectCode(error) ?? 0)
const dependencies = { makeSocket: makeUSyncSocket, loadAuth: authState, pause, now: Date.now }

export class WhatsAppSession {
  private socket?: ReturnType<typeof makeUSyncSocket>
  private auth?: Awaited<ReturnType<typeof authState>>
  private status: 'closed' | 'connecting' | 'pairing' | 'open' = 'closed'
  private starting?: Promise<void>
  private writing: Promise<void> = Promise.resolve()
  private storageFailed = false
  private busy = false
  private retryAfter = 0
  private revoked = false

  constructor(private ctx: DurableObjectState, private env: Env, private deps = dependencies) {}

  private async connect(pair = false) {
    if (this.storageFailed) throw new Error('Storage unavailable')
    if (this.status === 'open' || this.status === 'pairing') return
    if (this.starting) return this.starting
    if (this.deps.now() < this.retryAfter) throw new Error('Reconnect cooldown')
    this.starting = this.reconnect(pair).finally(() => { this.starting = undefined })
    return this.starting
  }

  private async reconnect(pair: boolean) {
    // On-demand only: no perpetual background timers or retry storm when idle.
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await this.start(pair)
        this.retryAfter = 0
        return
      } catch (error) {
        if (pair || this.revoked || this.storageFailed || !temporary(error) || attempt === 2) {
          this.retryAfter = this.deps.now() + 30_000
          throw error
        }
        await this.deps.pause(attempt === 0 ? 250 : 1000)
      }
    }
  }

  private async start(pair: boolean) {
    await this.writing
    this.revoked = !!await this.ctx.storage.get('session-revoked')
    if (this.revoked) throw new Error('Pairing required')
    this.auth ??= await this.deps.loadAuth(this.ctx.storage, this.env.SESSION_KEY)
    if (!pair && !this.auth.state.creds.account) throw new Error('Pairing required')
    this.status = 'connecting'
    const socket = this.deps.makeSocket({
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
        const error = Object.assign(new Error('Connection timeout'), { output: { statusCode: 408 } })
        socket.end(error)
        reject(error)
      }, 15_000)
      socket.ev.on('connection.update', update => {
        if (socket !== this.socket) return
        if (update.qr) {
          if (!pair) {
            socket.end(new Error('Pairing required'))
            reject(new Error('Pairing required'))
            return
          }
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
          const error = update.lastDisconnect?.error ?? new Error('Connection closed')
          if (disconnectCode(error) === 401) {
            this.revoked = true
            this.writing = this.writing.then(() => this.ctx.storage.put('session-revoked', true)).catch(() => { this.storageFailed = true })
            this.ctx.waitUntil(this.writing)
          }
          reject(error)
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
        if (this.env.ENABLE_PAIRING !== 'true') return reply({ error: 'pairing_disabled' }, 403)
        const phone = phoneFrom(request)
        if (!phone) return reply({ error: 'invalid_phone' }, 400)
        await this.writing
        if (this.revoked || await this.ctx.storage.get('session-revoked')) {
          await this.ctx.storage.deleteAll()
          this.auth = undefined
          this.revoked = false
        }
        this.retryAfter = 0
        await this.connect(true)
        if (this.auth!.state.creds.account) return reply({ error: 'already_paired' }, 409)
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
        try {
        await this.connect()
        if (this.status !== 'open') throw new Error('Pairing required')
        const result = await this.socket!.executeUSyncQuery(new USyncQuery()
          .withContactProtocol().withUser(new USyncUser().withPhone(`+${phone}`)))
        await this.writing
        if (this.storageFailed) throw new Error('Storage unavailable')
        return contactResult(result)
        } catch {
          this.socket?.end(new Error('Query failed'))
          throw new Error('WhatsApp unavailable')
        }
      })
    } catch {
      this.socket?.end(new Error('Session unavailable'))
      return reply({ error: 'whatsapp_unavailable' }, 503)
    } finally { this.busy = false }
  }
}
