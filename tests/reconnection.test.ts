import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { WhatsAppSession } from '../service/worker'

const api = 'a'.repeat(32), admin = 'b'.repeat(32)
const env = { API_KEY: api, ADMIN_KEY: admin, SESSION_KEY: 'ab'.repeat(32), ENABLE_PAIRING: 'false' } as any
const request = () => new Request('https://local/check?phone=5511999999999', { headers: { Authorization: `Bearer ${api}` } })
const failure = (code: number) => Object.assign(new Error('synthetic'), { output: { statusCode: code } })
function fixture(outcomes: (number | 'open')[], persistent = new Map<string, unknown>()) {
  let count = 0, time = 0, querying = 0
  const pauses: number[] = [], sockets: any[] = [], tasks: Promise<unknown>[] = []
  const storage = { get: async (key: string) => persistent.get(key), put: async (key: string, value: unknown) => { persistent.set(key, value) }, deleteAll: async () => persistent.clear() }
  const state = { creds: { account: {}, noiseKey: {} }, keys: {} }
  const deps = {
    now: () => time, pause: async (ms: number) => { pauses.push(ms); time += ms },
    loadAuth: async () => ({ state, saveCreds: async () => {} }),
    makeSocket() {
      count++
      const ev = new EventEmitter()
      const socket = { ev, requestPairingCode: async () => { throw new Error('must not pair') },
        executeUSyncQuery: async () => { querying++; return { list: [{ contact: true }] } },
        end(error: Error) { ev.emit('connection.update', { connection: 'close', lastDisconnect: { error } }) } }
      sockets.push(socket)
      const outcome = outcomes.shift() ?? 'open'
      queueMicrotask(() => outcome === 'open' ? ev.emit('connection.update', { connection: 'open' }) : socket.end(failure(outcome)))
      return socket
    }
  }
  const session = new WhatsAppSession({ storage, waitUntil: (p: Promise<unknown>) => tasks.push(p) } as any, env, deps as any)
  return { session, pauses, sockets, storage, deps, tasks, count: () => count, querying: () => querying, advance: (ms: number) => { time += ms } }
}
test('temporary connection failures recover with bounded progressive delays', async () => {
  const f = fixture([428, 503, 'open'])
  const response = await f.session.fetch(request())
  assert.equal(response.status, 200); assert.equal(await response.text(), 'true')
  assert.equal(f.count(), 3); assert.deepEqual(f.pauses, [250, 1000]); assert.equal(f.querying(), 1)
})
test('exhausted retries return 503, observe cooldown, and recover on later request', async () => {
  const f = fixture([408, 428, 503, 'open'])
  assert.equal((await f.session.fetch(request())).status, 503)
  assert.equal((await f.session.fetch(request())).status, 503)
  assert.equal(f.count(), 3); assert.equal(f.querying(), 0)
  f.advance(30001)
  assert.equal((await f.session.fetch(request())).status, 200)
  assert.equal(f.count(), 4)
})
test('an established session reconnects after a network drop without pairing again', async () => {
  const f = fixture(['open', 'open'])
  assert.equal((await f.session.fetch(request())).status, 200)
  f.sockets[0].end(failure(428))
  assert.equal((await f.session.fetch(request())).status, 200)
  assert.equal(f.count(), 2)
})
test('revocation is persisted, prevents retries, and survives instance restart', async () => {
  const persistent = new Map<string, unknown>()
  const f = fixture(['open'], persistent)
  assert.equal((await f.session.fetch(request())).status, 200)
  f.sockets[0].end(failure(401))
  await Promise.all(f.tasks)
  assert.equal((await f.session.fetch(request())).status, 503)
  assert.equal(f.count(), 1)
  const restarted = fixture(['open'], persistent)
  assert.equal((await restarted.session.fetch(request())).status, 503)
  assert.equal(restarted.count(), 0)
})
test('certificate or protocol failures do not trigger retries', async () => {
  const f = fixture([400])
  assert.equal((await f.session.fetch(request())).status, 503)
  assert.equal(f.count(), 1); assert.deepEqual(f.pauses, [])
})
test('parallel caller gets 429 while a connection is pending', async () => {
  const f = fixture(['open'])
  let release!: () => void
  f.deps.loadAuth = async () => { await new Promise<void>(resolve => { release = resolve }); return { state: { creds: { account: {} }, keys: {} } as any, saveCreds: async () => {} } }
  const first = f.session.fetch(request())
  // Wait until the first request reaches the fake auth gate.
  while (!release) await new Promise(resolve => setImmediate(resolve))
  assert.equal((await f.session.fetch(request())).status, 429)
  release()
  assert.equal((await first).status, 200)
  assert.equal(f.count(), 1)
})

test('explicit negative protocol response remains false after connection recovery', async () => {
  const f = fixture([428, 'open'])
  const create = f.deps.makeSocket
  f.deps.makeSocket = () => {
    const socket = create()
    socket.executeUSyncQuery = async () => ({ list: [{ contact: false }] })
    return socket
  }
  const response = await f.session.fetch(request())
  assert.equal(response.status, 200)
  assert.equal(await response.text(), 'false')
})
test('storage read failure returns 503 without connecting or generating identity', async () => {
  const f = fixture(['open'])
  f.deps.loadAuth = async () => { throw new Error('offline storage') }
  assert.equal((await f.session.fetch(request())).status, 503)
  assert.equal(f.count(), 0)
  assert.deepEqual(f.pauses, [])
})
