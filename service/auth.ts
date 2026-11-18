import { initAuthCreds } from '../src/Utils/auth-utils'
import { encryptedStorage } from './storage'
import { proto } from '../WAProto'
import type { AuthenticationState, AuthenticationCreds, SignalDataTypeMap } from '../src/Types'

export async function authState(storage: DurableObjectStorage, secret: string) {
  const encrypted = await encryptedStorage(storage, secret)
  const stored = await encrypted.read('creds')
  const creds: AuthenticationCreds = stored === undefined ? initAuthCreds() : stored
  for (const pair of [creds.noiseKey, creds.signedIdentityKey, creds.pairingEphemeralKeyPair, creds.signedPreKey?.keyPair]) {
    if (pair?.private?.length !== 32 || pair?.public?.length !== 32) throw new Error('Invalid stored credentials')
  }
  const saveCreds = () => encrypted.write('creds', creds)
  const state: AuthenticationState = {
    creds,
    keys: {
      async get(type, ids) {
        const data: Record<string, SignalDataTypeMap[typeof type]> = {}
        for (const id of ids) {
          let value = await encrypted.read(`${type}:${id}`) ?? null
          if (value && type === 'app-state-sync-key') value = proto.Message.AppStateSyncKeyData.fromObject(value)
          data[id] = value
        }
        return data
      },
      async set(data) {
        await storage.transaction(async txn => {
          for (const [type, entries] of Object.entries(data)) {
            for (const [id, value] of Object.entries(entries)) {
              const key = `${type}:${id}`
              if (value == null) await txn.delete(key)
              else await txn.put(key, await encrypted.encode(key, value))
            }
          }
        })
      }
    }
  }
  return { state, saveCreds }
}
