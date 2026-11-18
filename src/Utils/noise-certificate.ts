import { timingSafeEqual } from 'crypto'
import { proto } from '../../WAProto'
import { Curve } from './crypto'

// Pinned WhatsApp Noise trust anchor, independently matched against Baileys and whatsmeow.
const WHATSAPP_ROOT = Buffer.from('142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b', 'hex')

/** No network trust discovery, environment override, or fallback on validation failure. */
export function verifyServerCertificate(encoded: Uint8Array, serverStatic: Uint8Array) {
  return verifyCertificateChain(encoded, serverStatic, WHATSAPP_ROOT, Date.now())
}

// Explicit trust parameters are for deterministic unit tests. The connection uses the wrapper above.
export function verifyCertificateChain(encoded: Uint8Array, serverStatic: Uint8Array, root: Uint8Array, nowMs: number) {
  const fail = () => { throw new Error('Invalid Noise certificate') }
  const { intermediate, leaf } = proto.CertChain.decode(encoded)
  if (!intermediate?.details?.length || !leaf?.details?.length ||
      intermediate.signature?.length !== 64 || leaf.signature?.length !== 64 || serverStatic.length !== 32) fail()
  if (!Curve.verify(root, intermediate!.details!, intermediate!.signature!)) fail()
  const parent = proto.CertChain.NoiseCertificate.Details.decode(intermediate!.details!)
  if (parent.issuerSerial !== 0 || parent.key?.length !== 32 ||
      !Curve.verify(parent.key!, leaf!.details!, leaf!.signature!)) fail()
  const child = proto.CertChain.NoiseCertificate.Details.decode(leaf!.details!)
  if (child.issuerSerial !== parent.serial || child.key?.length !== 32 ||
      !timingSafeEqual(Buffer.from(child.key!), Buffer.from(serverStatic))) fail()
  for (const cert of [parent, child]) {
    const before = Number(cert.notBefore), after = Number(cert.notAfter)
    if (!Object.hasOwn(cert, 'notBefore') || !Object.hasOwn(cert, 'notAfter') ||
        !Number.isSafeInteger(before) || !Number.isSafeInteger(after) || before > after ||
        nowMs / 1000 < before || nowMs / 1000 > after) fail()
  }
}
