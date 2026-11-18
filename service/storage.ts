import { BufferJSON } from '../src/Utils/generics'

/** Encryption key lives in a Worker secret, never in the Durable Object database. */
export async function encryptedStorage(storage: DurableObjectStorage, secret: string) {
  if (!/^[a-f0-9]{64}$/i.test(secret ?? '')) throw new Error('Invalid session encryption key')
  const key = await crypto.subtle.importKey('raw', Buffer.from(secret, 'hex'), 'AES-GCM', false, ['encrypt', 'decrypt'])
  const aad = (name: string) => new TextEncoder().encode(`whatsapp-check:v1:${name}`)
  const encode = async (name: string, value: unknown) => {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode(JSON.stringify(value, BufferJSON.replacer))
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(name) }, key, plaintext)
    return JSON.stringify({ v: 1, iv: Buffer.from(iv).toString('base64'), data: Buffer.from(ciphertext).toString('base64') })
  }
  const read = async (name: string) => {
    const raw = await storage.get<string>(name)
    if (raw === undefined) return undefined
    const envelope = JSON.parse(raw)
    if (envelope.v !== 1 || typeof envelope.iv !== 'string' || typeof envelope.data !== 'string') throw new Error('Invalid encrypted record')
    const iv = Buffer.from(envelope.iv, 'base64')
    if (iv.length !== 12) throw new Error('Invalid encrypted record')
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(name) }, key, Buffer.from(envelope.data, 'base64'))
    return JSON.parse(new TextDecoder().decode(plaintext), BufferJSON.reviver)
  }
  return { read, encode, write: async (name: string, value: unknown) => storage.put(name, await encode(name, value)) }
}
