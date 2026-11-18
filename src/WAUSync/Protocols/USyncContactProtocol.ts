import { USyncQueryProtocol } from '../../Types/USync'
import { assertNodeErrorFree, BinaryNode } from '../../WABinary'
import { USyncUser } from '../USyncUser'

export class USyncContactProtocol implements USyncQueryProtocol {
	name = 'contact'

	getQueryElement(): BinaryNode {
		return {
			tag: 'contact',
			attrs: {},
		}
	}

	getUserElement(user: USyncUser): BinaryNode {
		//TODO: Implement type / username fields (not yet supported)
		return {
			tag: 'contact',
			attrs: {},
			content: user.phone,
		}
	}

	parser(node: BinaryNode): boolean {
		if(node.tag === 'contact') {
			assertNodeErrorFree(node)
			if (!['in', 'out'].includes(node.attrs.type)) {
                throw new Error('Unexpected contact response')
            }
            return node.attrs.type === 'in'
		}

		return false
	}
}