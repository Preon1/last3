export type AuthTransportHandlers = {
  onOpen: () => void
  onClose: () => void
  onError: () => void
  onMessage: (raw: string) => void
}

export type AuthTransportSocketState = {
  readyState: number
}

export class AuthTransportClient {
  private socket: AuthTransportSocketState | null = null
  private transport: any | null = null
  private controlWriter: WritableStreamDefaultWriter<Uint8Array> | null = null
  private datagramWriter: WritableStreamDefaultWriter<Uint8Array> | null = null
  private connectId = 0
  private notifyClose = true

  getSocket() {
    return this.socket
  }

  getReadyState() {
    return this.socket?.readyState ?? WebSocket.CLOSED
  }

  connect(url: string, handlers: AuthTransportHandlers) {
    this.disconnect(false)

    const WT = (window as any)?.WebTransport
    const state: AuthTransportSocketState = { readyState: WebSocket.CONNECTING }
    this.socket = state

    if (typeof WT !== 'function') {
      state.readyState = WebSocket.CLOSED
      handlers.onError()
      handlers.onClose()
      return state
    }

    const connectId = ++this.connectId
    this.notifyClose = true

    let transport: any
    try {
      transport = new WT(url)
    } catch {
      state.readyState = WebSocket.CLOSED
      handlers.onError()
      handlers.onClose()
      return state
    }

    this.transport = transport

    void Promise.resolve(transport.closed)
      .catch(() => null)
      .then(() => {
        if (connectId !== this.connectId) return
        state.readyState = WebSocket.CLOSED
        this.transport = null
        this.controlWriter = null
        this.datagramWriter = null
        if (this.notifyClose) handlers.onClose()
      })

    void (async () => {
      try {
        await transport.ready
        if (connectId !== this.connectId) return

        const controlStream = await transport.createBidirectionalStream()
        if (connectId !== this.connectId) return

        this.controlWriter = controlStream.writable.getWriter()

        if (transport?.datagrams?.writable && typeof transport.datagrams.writable.getWriter === 'function') {
          this.datagramWriter = transport.datagrams.writable.getWriter()
        }

        state.readyState = WebSocket.OPEN
        handlers.onOpen()

        void this.readStreamLines(controlStream.readable, connectId, handlers)
        if (transport?.datagrams?.readable) {
          void this.readDatagrams(transport.datagrams.readable, connectId, handlers)
        }
      } catch {
        if (connectId !== this.connectId) return
        handlers.onError()
        this.disconnect(true)
      }
    })()

    return state
  }

  private async readDatagrams(readable: ReadableStream<Uint8Array>, connectId: number, handlers: AuthTransportHandlers) {
    const reader = readable.getReader()
    const decoder = new TextDecoder()
    try {
      while (connectId === this.connectId) {
        const { value, done } = await reader.read()
        if (done) break
        if (!value) continue
        const text = decoder.decode(value)
        if (text) handlers.onMessage(text)
      }
    } catch {
      // ignore
    } finally {
      try {
        reader.releaseLock()
      } catch {
        // ignore
      }
    }
  }

  private async readStreamLines(readable: ReadableStream<Uint8Array>, connectId: number, handlers: AuthTransportHandlers) {
    const reader = readable.getReader()
    const decoder = new TextDecoder()
    let acc = ''

    try {
      while (connectId === this.connectId) {
        const { value, done } = await reader.read()
        if (done) break
        if (!value) continue
        acc += decoder.decode(value, { stream: true })

        while (true) {
          const idx = acc.indexOf('\n')
          if (idx < 0) break
          const line = acc.slice(0, idx).trim()
          acc = acc.slice(idx + 1)
          if (line) handlers.onMessage(line)
        }
      }

      const tail = acc.trim()
      if (tail) handlers.onMessage(tail)
    } catch {
      // ignore
    } finally {
      try {
        reader.releaseLock()
      } catch {
        // ignore
      }
    }
  }

  disconnect(emitClose = false) {
    this.notifyClose = emitClose
    this.connectId += 1

    const state = this.socket
    if (state) state.readyState = WebSocket.CLOSING

    try {
      this.controlWriter?.close()
    } catch {
      // ignore
    }
    try {
      this.datagramWriter?.close()
    } catch {
      // ignore
    }
    try {
      this.transport?.close?.()
    } catch {
      // ignore
    }

    this.transport = null
    this.controlWriter = null
    this.datagramWriter = null
    if (state) state.readyState = WebSocket.CLOSED
    this.socket = null
  }

  sendJson(obj: unknown) {
    const writer = this.controlWriter
    if (!writer || this.getReadyState() !== WebSocket.OPEN) return

    let frame = ''
    try {
      frame = `${JSON.stringify(obj)}\n`
    } catch {
      return
    }

    void writer.write(new TextEncoder().encode(frame)).catch(() => {
      // ignore
    })
  }

  sendDatagramJson(obj: unknown) {
    const writer = this.datagramWriter
    if (!writer || this.getReadyState() !== WebSocket.OPEN) {
      this.sendJson(obj)
      return
    }

    let text = ''
    try {
      text = JSON.stringify(obj)
    } catch {
      return
    }

    void writer.write(new TextEncoder().encode(text)).catch(() => {
      // ignore
    })
  }
}
