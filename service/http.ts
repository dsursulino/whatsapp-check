export function reply(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { 'Cache-Control': 'no-store' } })
}

export async function authorized(request: Request, secret?: string) {
  if (!secret || secret.length < 32) return false
  const actual = request.headers.get('Authorization') ?? ''
  const hash = async (s: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))
  const [a, b] = await Promise.all([hash(actual), hash(`Bearer ${secret}`)])
  return a.reduce((difference, byte, i) => difference | (byte ^ b[i]), 0) === 0
}

export function phoneFrom(request: Request) {
  const values = new URL(request.url).searchParams.getAll('phone')
  if (values.length !== 1 || !/^[1-9][0-9]{7,14}$/.test(values[0])) return undefined
  return values[0]
}

export function contactResult(result: { list: Record<string, unknown>[] } | undefined): boolean {
  if (!result || result.list.length !== 1 || typeof result.list[0].contact !== 'boolean') {
    throw new Error('Invalid WhatsApp response')
  }
  return result.list[0].contact
}

export async function route(request: Request, secret: string | undefined, check: (phone: string) => Promise<boolean>) {
  if (new URL(request.url).pathname !== '/check') return reply({ error: 'not_found' }, 404)
  if (request.method !== 'GET') return reply({ error: 'method_not_allowed' }, 405)
  if (!await authorized(request, secret)) return reply({ error: 'unauthorized' }, 401)
  const phone = phoneFrom(request)
  if (!phone) return reply({ error: 'invalid_phone' }, 400)
  try { return reply(await check(phone)) }
  catch { return reply({ error: 'whatsapp_unavailable' }, 503) }
}
