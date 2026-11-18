import { proto } from '../../WAProto'
import { NOISE_MODE } from '../Defaults'
import { KeyPair } from '../Types'
import { BinaryNode, decodeBinaryNode } from '../WABinary'
import { aesDecryptGCM, aesEncryptGCM, Curve, hkdf, sha256 } from './crypto'
import { ILogger } from './logger'
import { verifyServerCertificate } from './noise-certificate'

export const MAX_NOISE_FRAME = 1024 * 1024

const generateIV = (counter: number) => {
	const iv = new ArrayBuffer(12)
	new DataView(iv).setUint32(8, counter)

	return new Uint8Array(iv)
}

export const makeNoiseHandler = ({
	keyPair: { private: privateKey, public: publicKey },
	NOISE_HEADER,
	logger,
	routingInfo
}: {
	keyPair: KeyPair
	NOISE_HEADER: Uint8Array
	logger: ILogger
	routingInfo?: Buffer | undefined
}) => {
	logger = logger.child({ class: 'ns' })

	const authenticate = (data: Uint8Array) => {
		if(!isFinished) {
			hash = sha256(Buffer.concat([hash, data]))
		}
	}

	const encrypt = async (plaintext: Uint8Array) => { //CF
		if (writeCounter >= 0x100000000) throw new Error('Noise counter exhausted')
        const counter = writeCounter++
        const result = await aesEncryptGCM(plaintext, encKey, generateIV(counter), hash)

		authenticate(result)
		return result
	}

	const decrypt = async (ciphertext: Uint8Array) => { //CF
		// before the handshake is finished, we use the same counter
		// after handshake, the counters are different
		const counter = isFinished ? readCounter++ : writeCounter++
        if (counter >= 0x100000000) throw new Error('Noise counter exhausted')
        const iv = generateIV(counter)
		const result = await aesDecryptGCM(ciphertext, decKey, iv, hash) //CF

		authenticate(ciphertext)
		return result
	}

	const localHKDF = async(data: Uint8Array) => {
		const key = await hkdf(Buffer.from(data), 64, { salt, info: '' })
		return [key.slice(0, 32), key.slice(32)]
	}

	const mixIntoKey = async(data: Uint8Array) => {
		const [write, read] = await localHKDF(data)
		salt = write
		encKey = read
		decKey = read
		readCounter = 0
		writeCounter = 0
	}

	const finishInit = async() => {
		const [write, read] = await localHKDF(new Uint8Array(0))
		encKey = write
		decKey = read
		hash = Buffer.from([])
		readCounter = 0
		writeCounter = 0
		isFinished = true
        if (pendingFrames) await processFrames(pendingFrames)
	}

	const data = Buffer.from(NOISE_MODE)
	let hash = data.byteLength === 32 ? data : sha256(data)
	let salt = hash
	let encKey = hash
	let decKey = hash
	let readCounter = 0
	let writeCounter = 0
	let isFinished = false
	let sentIntro = false

	let inBytes = Buffer.alloc(0)
    let receivedHello = false
    let pendingFrames: ((buff: Uint8Array | BinaryNode) => void) | undefined

	authenticate(NOISE_HEADER)
	authenticate(publicKey)

    const processFrames = async(onFrame: (buff: Uint8Array | BinaryNode) => void) => {
        while (inBytes.length >= 3) {
            const size = inBytes.readUIntBE(0, 3)
            if (!size || size > MAX_NOISE_FRAME) throw new Error('Invalid Noise frame length')
            if (!isFinished && receivedHello) return
            if (inBytes.length < size + 3) return
            const bytes = inBytes.subarray(3, size + 3)
            inBytes = inBytes.subarray(size + 3)
            if (isFinished) onFrame(await decodeBinaryNode(await decrypt(bytes)))
            else { receivedHello = true; onFrame(bytes) }
        }
    }

	return {
		encrypt,
		decrypt,
		authenticate,
		mixIntoKey,
		finishInit,
		processHandshake: async({ serverHello }: proto.HandshakeMessage, noiseKey: KeyPair) => {
			if (serverHello?.ephemeral?.length !== 32 || !serverHello.static?.length || !serverHello.payload?.length) {
                throw new Error('Invalid Noise handshake')
            }
			authenticate(serverHello.ephemeral)
			await mixIntoKey(Curve.sharedKey(privateKey, serverHello!.ephemeral!))

			const decStaticContent = await decrypt(serverHello!.static!)
            if (decStaticContent.length !== 32) throw new Error('Invalid Noise key')
			await mixIntoKey(Curve.sharedKey(privateKey, decStaticContent))

			const certDecoded = await decrypt(serverHello!.payload!) //CF

			verifyServerCertificate(certDecoded, decStaticContent)

			const keyEnc = await encrypt(noiseKey.public) //CF
			await mixIntoKey(Curve.sharedKey(noiseKey.private, serverHello!.ephemeral!))

			return keyEnc
		},
		encodeFrame: async(data: Buffer | Uint8Array) => {
            if (data.byteLength > MAX_NOISE_FRAME - 16) throw new Error('Noise frame too large')
			/*CF if(isFinished) {
				data = encrypt(data)
			} */

			if(isFinished) data = await encrypt(data)

			let header: Buffer

			if(routingInfo) {
				header = Buffer.alloc(7)
				header.write('ED', 0, 'utf8')
				header.writeUint8(0, 2)
				header.writeUint8(1, 3)
				header.writeUint8(routingInfo.byteLength >> 16, 4)
				header.writeUint16BE(routingInfo.byteLength & 65535, 5)
				header = Buffer.concat([header, routingInfo, NOISE_HEADER])
			} else {
				header = Buffer.from(NOISE_HEADER)
			}

			const introSize = sentIntro ? 0 : header.length
			const frame = Buffer.alloc(introSize + 3 + data.byteLength)

			if(!sentIntro) {
				frame.set(header)
				sentIntro = true
			}

			frame.writeUInt8(data.byteLength >> 16, introSize)
			frame.writeUInt16BE(65535 & data.byteLength, introSize + 1)
			frame.set(data, introSize + 3)

			return frame
		},
        decodeFrame: async(newData: Buffer | Uint8Array, onFrame: (buff: Uint8Array | BinaryNode) => void) => {
            if (inBytes.length + newData.byteLength > MAX_NOISE_FRAME + 3) throw new Error('Noise buffer too large')
            pendingFrames = onFrame
            inBytes = Buffer.concat([inBytes, newData])
            await processFrames(onFrame)
        }
    }
}
