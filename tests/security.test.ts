import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, createCipheriv, hkdfSync } from 'crypto'
import { proto } from '../WAProto'
import { Curve, aesEncryptGCM, aesDecryptGCM, hkdf } from '../src/Utils/crypto'
import { verifyCertificateChain, verifyServerCertificate } from '../src/Utils/noise-certificate'
import { encryptedStorage } from '../service/storage'
import { decompressingIfRequired, MAX_DECOMPRESSED } from '../src/WABinary/decode'
import { deflate } from 'pako'
import { makeNoiseHandler } from '../src/Utils/noise-handler'

function certificate() {
  const root = Curve.generateKeyPair(), intermediate = Curve.generateKeyPair(), server = Curve.generateKeyPair()
  const now = Math.floor(Date.now() / 1000)
  const details = (key: Uint8Array, serial: number, issuerSerial: number, before = now - 10, after = now + 3600) =>
    proto.CertChain.NoiseCertificate.Details.encode({ key, serial, issuerSerial, notBefore: before, notAfter: after }).finish()
  const parent = details(intermediate.public, 7, 0), leaf = details(server.public, 8, 7)
  const chain = { intermediate: { details: parent, signature: Curve.sign(root.private, parent) }, leaf: { details: leaf, signature: Curve.sign(intermediate.private, leaf) } }
  return { root, intermediate, server, now, details, chain, encode: () => proto.CertChain.encode(chain).finish() }
}
test('Noise validates complete chain, key binding, dates and pinned root', () => {
  const c = certificate()
  const verify = () => verifyCertificateChain(c.encode(), c.server.public, c.root.public, c.now * 1000)
  verify()
  assert.throws(() => verifyServerCertificate(c.encode(), c.server.public))
  assert.throws(() => verifyCertificateChain(c.encode(), randomBytes(32), c.root.public, c.now * 1000))
  assert.throws(() => verifyCertificateChain(c.encode(), c.server.public, c.root.public, (c.now + 4000) * 1000))
  c.chain.leaf.signature[0] ^= 1
  assert.throws(verify)
  c.chain.leaf.signature[0] ^= 1
  c.chain.intermediate.signature[0] ^= 1
  assert.throws(verify)
})
test('Noise rejects a validly signed leaf with incorrect issuer', () => {
  const c = certificate()
  c.chain.leaf.details = c.details(c.server.public, 8, 99)
  c.chain.leaf.signature = Curve.sign(c.intermediate.private, c.chain.leaf.details)
  assert.throws(() => verifyCertificateChain(c.encode(), c.server.public, c.root.public, c.now * 1000))
})
test('X25519 rejects low order peer key', () => {
  assert.throws(() => Curve.sharedKey(Curve.generateKeyPair().private, Buffer.alloc(32)))
})
test('AES-GCM and HKDF match independent Node implementations; tampering rejected', async () => {
  const key = randomBytes(32), iv = randomBytes(12), aad = randomBytes(7), text = randomBytes(40)
  const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad)
  const expected = Buffer.concat([cipher.update(text), cipher.final(), cipher.getAuthTag()])
  const actual = await aesEncryptGCM(text, key, iv, aad)
  assert.deepEqual(actual, expected)
  assert.deepEqual(await aesDecryptGCM(actual, key, iv, aad), text)
  actual[0] ^= 1
  await assert.rejects(() => aesDecryptGCM(actual, key, iv, aad))
  assert.deepEqual(await hkdf(text, 64, { salt: key, info: 'test' }), Buffer.from(hkdfSync('sha256', text, key, 'test', 64)))
})
test('encrypted records hide secrets and reject mutation, relocation, wrong key and plaintext', async () => {
  const data = new Map<string, string>()
  const raw = { get: async (key: string) => data.get(key), put: async (key: string, value: string) => { data.set(key, value) } } as any
  const store = await encryptedStorage(raw, 'ab'.repeat(32))
  await store.write('creds', { private: 'PRIVATE_CANARY_7283' })
  assert.ok(!data.get('creds')!.includes('PRIVATE_CANARY_7283'))
  assert.deepEqual(await store.read('creds'), { private: 'PRIVATE_CANARY_7283' })
  data.set('other', data.get('creds')!)
  await assert.rejects(() => store.read('other'))
  const wrong = await encryptedStorage(raw, 'cd'.repeat(32))
  await assert.rejects(() => wrong.read('creds'))
  const envelope = JSON.parse(data.get('creds')!); const bytes = Buffer.from(envelope.data, 'base64'); bytes[0] ^= 1
  envelope.data = bytes.toString('base64'); data.set('creds', JSON.stringify(envelope))
  await assert.rejects(() => store.read('creds'))
  data.set('creds', '{"private":"plaintext"}')
  await assert.rejects(() => store.read('creds'))
})
test('compressed bomb and oversized Noise frame fail closed', async () => {
  const bomb = Buffer.concat([Buffer.from([2]), Buffer.from(deflate(Buffer.alloc(MAX_DECOMPRESSED + 1)))])
  await assert.rejects(() => decompressingIfRequired(bomb))
  const silent = { level: 'silent', child() { return this }, trace() {} } as any
  const handler = makeNoiseHandler({ keyPair: Curve.generateKeyPair(), NOISE_HEADER: Buffer.from([87,65,6,2]), logger: silent })
  await assert.rejects(() => handler.decodeFrame(Buffer.from([255,255,255]), () => assert.fail('must not deliver')))
})
