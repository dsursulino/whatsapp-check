import { initAuthCreds } from '../src/Utils/auth-utils'
import { BufferJSON } from '../src/Utils/generics'
import { proto } from '../WAProto'
import type { AuthenticationState, AuthenticationCreds, SignalDataTypeMap } from '../src/Types'

export async function authState(storage: DurableObjectStorage) {
  const stored = await storage.get<string>('creds')
  const creds: AuthenticationCreds = stored === undefined ? initAuthCreds() : JSON.parse(stored, BufferJSON.reviver)
  const saveCreds = () => storage.put('creds', JSON.stringify(creds, BufferJSON.replacer))
  const state: AuthenticationState = {
    creds,
    keys: {
      async get(type, ids) {
        const data: Record<string, SignalDataTypeMap[typeof type]> = {}
        const stored = await storage.get<string>(ids.map(id => `${type}:${id}`))
        for (const id of ids) {
          const serialized = stored.get(`${type}:${id}`)
          let value = serialized === undefined ? null : JSON.parse(serialized, BufferJSON.reviver)
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
              else await txn.put(key, JSON.stringify(value, BufferJSON.replacer))
            }
          }
        })
      }
    }
  }
  return { state, saveCreds }
}
