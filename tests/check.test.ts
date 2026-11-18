import { test } from 'node:test'
import assert from 'node:assert/strict'
import { route, contactResult } from '../service/http'
import { authState } from '../service/auth'
import { Curve } from '../src/Utils/crypto'
import { USyncContactProtocol } from '../src/WAUSync/Protocols/USyncContactProtocol'

const secret = 'test-only-key-with-at-least-32-characters'
const request = (query = 'phone=5511999999999', key = secret) => new Request(`https://check.test/check?${query}`, {
  headers: { Authorization: `Bearer ${key}` }
})
for (const exists of [true, false]) test(`returns literal ${exists}`, async () => {
  const response = await route(request(), secret, async phone => { assert.equal(phone, '5511999999999'); return exists })
  assert.equal(response.status, 200)
  assert.equal(await response.text(), String(exists))
  assert.equal(response.headers.get('cache-control'), 'no-store')
})
test('rejects invalid authentication without consulting WhatsApp', async () => {
  let calls = 0
  for (const key of ['', 'wrong']) {
    const response = await route(request(undefined, key), secret, async () => { calls++; return true })
    assert.equal(response.status, 401)
  }
  assert.equal(calls, 0)
})
test('missing server key fails closed', async () => {
  assert.equal((await route(request(), undefined, async () => true)).status, 401)
})
test('rejects malformed and duplicate numbers before consulting', async () => {
  for (const query of ['', 'phone=abc', 'phone=0123456789', 'phone=5511999999999&phone=5511888888888', 'phone=5511999999999999']) {
    const response = await route(request(query), secret, async () => { throw new Error('must not call') })
    assert.equal(response.status, 400)
  }
})
test('WhatsApp failures are 503, never false', async () => {
  const response = await route(request(), secret, async () => { throw new Error('secret error details') })
  assert.equal(response.status, 503)
  assert.equal(await response.text(), '{"error":"whatsapp_unavailable"}')
})
test('only explicit contact result is a boolean', () => {
  for (const value of [true, false]) assert.equal(contactResult({ list: [{ contact: value }] }), value)
  for (const value of [undefined, { list: [] }, { list: [{}] }, { list: [{ contact: 'true' }] }]) {
    assert.throws(() => contactResult(value))
  }
  const parser = new USyncContactProtocol()
  assert.equal(parser.parser({ tag: 'contact', attrs: { type: 'out' } }), false)
  assert.throws(() => parser.parser({ tag: 'contact', attrs: { type: 'unknown' } }))
})
test('rejects forged signature and accepts genuine signature', () => {
  const pair = Curve.generateKeyPair()
  const message = Buffer.from('whatsapp-check')
  const signature = Curve.sign(pair.private, message)
  assert.equal(Curve.verify(pair.public, message, signature), true)
  signature[0] ^= 1
  assert.equal(Curve.verify(pair.public, message, signature), false)
})
function memoryStorage() {
  const data = new Map<string, string>()
  const storage = {
    async get(key: string | string[]) { return Array.isArray(key) ? new Map(key.filter(k => data.has(k)).map(k => [k, data.get(k)])) : data.get(key) },
    async put(key: string, value: string) { data.set(key, value) },
    async delete(key: string) { return data.delete(key) },
    async transaction(fn: (storage: unknown) => Promise<void>) { await fn(storage) }
  }
  return storage
}
test('auth and Signal keys survive reload, including binary values and deletions', async () => {
  const storage = memoryStorage()
  const first = await authState(storage as any, 'ab'.repeat(32))
  await first.saveCreds()
  await first.state.keys.set({ session: { contact: Buffer.from([1, 2, 3]) } })
  const second = await authState(storage as any, 'ab'.repeat(32))
  assert.deepEqual(second.state.creds.noiseKey, first.state.creds.noiseKey)
  assert.deepEqual((await second.state.keys.get('session', ['contact'])).contact, Buffer.from([1, 2, 3]))
  await second.state.keys.set({ session: { contact: null } })
  assert.equal((await second.state.keys.get('session', ['contact'])).contact, null)
})
test('storage failure does not create a replacement identity', async () => {
  await assert.rejects(() => authState({ get: async () => { throw new Error('offline') } } as any, 'ab'.repeat(32)))
})

test('WebSocket refuses destinations outside WhatsApp without network access', async () => {
  const { WebSocketClient } = await import('../src/Socket/Client/websocket')
  const originalFetch = globalThis.fetch
  let calls = 0
  globalThis.fetch = async () => { calls++; throw new Error('unexpected fetch') }
  try {
    for (const url of ['wss://attacker.example/ws/chat', 'wss://web.whatsapp.com.attacker.example/ws/chat', 'ws://web.whatsapp.com/ws/chat', 'wss://web.whatsapp.com/other']) {
      const socket = new WebSocketClient(new URL(url), {} as any)
      let failed = false
      socket.on('error', () => { failed = true })
      await socket.connect()
      assert.equal(failed, true)
    }
    assert.equal(calls, 0)
  } finally { globalThis.fetch = originalFetch }
})

test('negative WhatsApp contact types pass through USync parsing and HTTP as false', async () => {
  const { USyncQuery } = await import('../src/WAUSync')
  for (const type of ['out', 'invalid']) {
    const query = new USyncQuery().withContactProtocol()
    const result = query.parseUSyncQueryResult({ tag: 'iq', attrs: { type: 'result' }, content: [
      { tag: 'usync', attrs: {}, content: [{ tag: 'list', attrs: {}, content: [
        { tag: 'user', attrs: {}, content: [{ tag: 'contact', attrs: { type } }] }
      ] }] }
    ] })
    const response = await route(request(), secret, async () => contactResult(result))
    assert.equal(response.status, 200)
    assert.equal(await response.text(), 'false')
  }
})
