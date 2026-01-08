import { computed, ref } from 'vue'

export type PresenceUser = {
  id: string
  name: string | null
  busy: boolean
}

type ChatMsg = {
  type: 'chat'
  id?: string
  atIso: string
  fromName: string
  toName?: string | null
  private: boolean
  text: string
}

type InboundMsgAny = { type?: unknown; [k: string]: unknown }

function asObj(v: unknown): InboundMsgAny | null {
  if (!v || typeof v !== 'object') return null
  return v as InboundMsgAny
}

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

function asBool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null
}

function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const path = import.meta.env.DEV ? '/ws' : ''
  return `${proto}//${location.host}${path}`
}

export function useSignaling() {
  const ws = ref<WebSocket | null>(null)

  const connected = computed(() => ws.value?.readyState === WebSocket.OPEN)
  const myId = ref<string | null>(null)
  const myName = ref<string | null>(null)

  const status = ref<string>('')
  const users = ref<PresenceUser[]>([])
  const chat = ref<ChatMsg[]>([])

  function send(obj: unknown) {
    if (!ws.value || ws.value.readyState !== WebSocket.OPEN) return
    ws.value.send(JSON.stringify(obj))
  }

  function disconnect() {
    try {
      ws.value?.close()
    } catch {
      // ignore
    }
    ws.value = null
    myId.value = null
    myName.value = null
    users.value = []
    chat.value = []
  }

  function connect(name: string) {
    const desiredName = name.trim()
    if (!desiredName) {
      status.value = 'Enter a name.'
      return
    }

    status.value = 'Connecting…'
    disconnect()

    const sock = new WebSocket(wsUrl())
    ws.value = sock

    sock.addEventListener('open', () => {
      send({ type: 'setName', name: desiredName })
    })

    sock.addEventListener('message', (ev) => {
      let obj: InboundMsgAny | null
      try {
        obj = asObj(JSON.parse(String(ev.data)))
      } catch {
        return
      }

      if (!obj) return

      const type = asString(obj.type)
      if (!type) return

      if (type === 'hello') {
        const id = asString(obj.id)
        if (id) myId.value = id
        return
      }

      if (type === 'nameResult') {
        const ok = asBool(obj.ok)
        const name = asString(obj.name)
        const reason = asString(obj.reason)
        if (ok && name) {
          myName.value = name
          status.value = ''
        } else {
          status.value = reason === 'taken' ? 'Name is taken.' : 'Invalid name.'
        }
        return
      }

      if (type === 'presence') {
        users.value = Array.isArray(obj.users) ? (obj.users as PresenceUser[]) : []
        return
      }

      if (type === 'chat') {
        const atIso = asString(obj.atIso)
        const fromName = asString(obj.fromName)
        const text = asString(obj.text)
        const isPrivate = asBool(obj.private)
        const id = asString(obj.id)

        if (!atIso || !fromName || !text || isPrivate === null) return

        const toNameRaw = obj.toName
        const toName = toNameRaw === null ? null : asString(toNameRaw)

        const msg: ChatMsg = {
          type: 'chat',
          ...(id ? { id } : {}),
          atIso,
          fromName,
          ...(toName !== null && toName !== undefined ? { toName } : {}),
          private: isPrivate,
          text,
        }

        chat.value.push(msg)
        return
      }

      if (type === 'error') {
        // Keep this minimal for now.
        const code = asString(obj.code)
        if (code === 'NO_NAME') status.value = 'Enter a name.'
        return
      }
    })

    sock.addEventListener('close', () => {
      // Keep user-facing message simple.
      if (myName.value) status.value = 'Disconnected.'
    })

    sock.addEventListener('error', () => {
      status.value = 'Connection error.'
    })
  }

  function sendChat(text: string) {
    const t = text.trim()
    if (!t) return
    send({ type: 'chatSend', text: t })
  }

  return {
    connected,
    myId,
    myName,
    status,
    users,
    chat,
    connect,
    disconnect,
    sendChat,
  }
}
