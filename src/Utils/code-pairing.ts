import { randomBytes } from 'crypto'
import { Boom } from '@hapi/boom'
import { getBinaryNodeChild, getBinaryNodeChildBuffer, S_WHATSAPP_NET } from '../WABinary'
import { aesDecryptCTR, aesEncryptGCM, Curve, derivePairingCodeKey, hkdf } from './crypto'
import type { AuthenticationState } from '../Types'
import type { BinaryNode } from '../WABinary'

export async function finishCodePairing(node: BinaryNode, authState: AuthenticationState, query: (node: BinaryNode) => Promise<unknown>, generateMessageTag: () => string, ev: { emit: Function }) {
  if (!authState.creds.pairingCode || authState.creds.account) throw new Error('Unexpected pairing message')
			const linkCodeCompanionReg = getBinaryNodeChild(node, 'link_code_companion_reg')
			const ref = toRequiredBuffer(getBinaryNodeChildBuffer(linkCodeCompanionReg, 'link_code_pairing_ref'))
			const primaryIdentityPublicKey = toRequiredBuffer(getBinaryNodeChildBuffer(linkCodeCompanionReg, 'primary_identity_pub'))
			const primaryEphemeralPublicKeyWrapped = toRequiredBuffer(getBinaryNodeChildBuffer(linkCodeCompanionReg, 'link_code_pairing_wrapped_primary_ephemeral_pub'))
			if (primaryIdentityPublicKey.length !== 32 || primaryEphemeralPublicKeyWrapped.length !== 80 || ref.length > 1024) throw new Error('Invalid pairing payload')
            const codePairingPublicKey = await decipherLinkPublicKey(primaryEphemeralPublicKeyWrapped)
			const companionSharedKey = Curve.sharedKey(authState.creds.pairingEphemeralKeyPair.private, codePairingPublicKey)
			const random = randomBytes(32)
			const linkCodeSalt = randomBytes(32)
			const linkCodePairingExpanded = await hkdf(companionSharedKey, 32, {
				salt: linkCodeSalt,
				info: 'link_code_pairing_key_bundle_encryption_key'
			})
			const encryptPayload = Buffer.concat([Buffer.from(authState.creds.signedIdentityKey.public), primaryIdentityPublicKey, random])
			const encryptIv = randomBytes(12)
			const encrypted = await aesEncryptGCM(encryptPayload, linkCodePairingExpanded, encryptIv, Buffer.alloc(0))
			const encryptedPayload = Buffer.concat([linkCodeSalt, encryptIv, encrypted])
			const identitySharedKey = Curve.sharedKey(authState.creds.signedIdentityKey.private, primaryIdentityPublicKey)
			const identityPayload = Buffer.concat([companionSharedKey, identitySharedKey, random])
			authState.creds.advSecretKey = (await hkdf(identityPayload, 32, { info: 'adv_secret' })).toString('base64')
			await query({
				tag: 'iq',
				attrs: {
					to: S_WHATSAPP_NET,
					type: 'set',
					id: generateMessageTag(),
					xmlns: 'md'
				},
				content: [
					{
						tag: 'link_code_companion_reg',
						attrs: {
							jid: authState.creds.me!.id,
							stage: 'companion_finish',
						},
						content: [
							{
								tag: 'link_code_pairing_wrapped_key_bundle',
								attrs: {},
								content: encryptedPayload
							},
							{
								tag: 'companion_identity_public',
								attrs: {},
								content: authState.creds.signedIdentityKey.public
							},
							{
								tag: 'link_code_pairing_ref',
								attrs: {},
								content: ref
							}
						]
					}
				]
			})
			authState.creds.registered = true
			ev.emit('creds.update', authState.creds)
	async function decipherLinkPublicKey(data: Uint8Array | Buffer) {
		const buffer = toRequiredBuffer(data)
		const salt = buffer.slice(0, 32)
		const secretKey = await derivePairingCodeKey(authState.creds.pairingCode!, salt)
		const iv = buffer.slice(32, 48)
		const payload = buffer.slice(48, 80)
		return aesDecryptCTR(payload, secretKey, iv)
	}


	function toRequiredBuffer(data: Uint8Array | Buffer | undefined) {
		if(data === undefined) {
			throw new Boom('Invalid buffer', { statusCode: 400 })
		}

		return data instanceof Buffer ? data : Buffer.from(data)
	}

}
