import { DEFAULT_ORIGIN } from '../../Defaults'
import { AbstractSocketClient } from './types'

export class WebSocketClient extends AbstractSocketClient {
  protected socket: WebSocket | null = null
  private stopped = false
  get isOpen() { return this.socket?.readyState === WebSocket.OPEN }
  get isClosed() { return !this.socket || this.socket.readyState === WebSocket.CLOSED }
  get isClosing() { return !this.socket || this.socket.readyState === WebSocket.CLOSING }
  get isConnecting() { return this.socket?.readyState === WebSocket.CONNECTING }

  async connect(): Promise<void> {
    if (this.socket) return
    try {
      if (this.url.protocol !== 'wss:' || this.url.hostname !== 'web.whatsapp.com' ||
          this.url.port || this.url.pathname !== '/ws/chat' || this.url.username || this.url.password) {
        throw new Error('Destination not allowed')
      }
      const response = await fetch(this.url.href.replace('wss://', 'https://'), {
        headers: { origin: DEFAULT_ORIGIN, Upgrade: 'websocket' },
        redirect: 'error',
        signal: AbortSignal.timeout(this.config.connectTimeoutMs)
      }) as Response & { webSocket?: WebSocket & { accept(): void } }
      const socket = response.webSocket
      if (!socket) throw new Error('WebSocket upgrade failed')
      if (this.stopped) { socket.accept(); socket.close(); return }
      this.socket = socket
      socket.addEventListener('message', event => {
        this.emit('message', event.data instanceof ArrayBuffer ? Buffer.from(event.data) : event.data)
      })
      socket.addEventListener('error', () => this.emit('error', new Error('WebSocket error')))
      socket.addEventListener('close', () => this.emit('close'))
      socket.accept()
      this.emit('open')
    } catch {
      this.emit('error', new Error('WebSocket connection failed'))
    }
  }
  async close() {
    this.stopped = true
    this.socket?.close()
    this.socket = null
  }
  send(data: string | Uint8Array): boolean {
    if (!this.isOpen) throw new Error('WebSocket closed')
    this.socket!.send(data)
    return true
  }
}
