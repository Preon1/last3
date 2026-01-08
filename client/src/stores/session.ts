import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { useUiStore } from './ui'
import { i18n } from '../i18n'
import { notify, vibrate } from '../utils/notify'
import { useToastStore } from './toast'

export type PresenceUser = {
  id: string
  name: string | null
  busy: boolean
}

export type ChatMsg = {
  type: 'chat'
  id?: string
  atIso: string
  fromName: string
  toName?: string | null
  private: boolean
  text: string
}

export type VoiceInfo = {
  turnHost?: string
  relayPortsTotal?: number | null
  relayPortsUsedEstimate?: number
  maxConferenceUsersEstimate?: number
  capacityCallsEstimate?: number
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

function asNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

function asVoiceInfo(v: unknown): VoiceInfo | null {
  const o = asObj(v)
  if (!o) return null

  const turnHost = asString(o.turnHost)

  const relayPortsTotal = o.relayPortsTotal === null ? null : asNumber(o.relayPortsTotal)
  const relayPortsUsedEstimate = asNumber(o.relayPortsUsedEstimate)
  const maxConferenceUsersEstimate = asNumber(o.maxConferenceUsersEstimate)
  const capacityCallsEstimate = asNumber(o.capacityCallsEstimate)

  return {
    ...(turnHost ? { turnHost } : {}),
    ...(o.relayPortsTotal === null ? { relayPortsTotal: null } : {}),
    ...(relayPortsTotal !== null ? { relayPortsTotal } : {}),
    ...(relayPortsUsedEstimate !== null ? { relayPortsUsedEstimate } : {}),
    ...(maxConferenceUsersEstimate !== null ? { maxConferenceUsersEstimate } : {}),
    ...(capacityCallsEstimate !== null ? { capacityCallsEstimate } : {}),
  }
}

function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}`
}

export const useSessionStore = defineStore('session', () => {
  const ui = useUiStore()
  const toast = useToastStore()
  const ws = ref<WebSocket | null>(null)

  const pingTimer = ref<number | null>(null)

  const outboxTimer = ref<number | null>(null)
  const outbox = new Map<
    string,
    {
      json: string
      attempts: number
      nextAt: number
      maxAttempts: number
      fixedDelayMs?: number
      kind?: string
    }
  >()

  const OUTBOX_DEFAULT_MAX_ATTEMPTS = 6
  const OUTBOX_DEFAULT_BASE_DELAY_MS = 600
  const OUTBOX_DEFAULT_MAX_DELAY_MS = 8000

  const seenMsgIds = new Set<string>()
  const seenMsgIdQueue: string[] = []
  const SEEN_MSGIDS_MAX = 2000

  function calcOutboxDelayMs(attempts: number, fixedDelayMs?: number) {
    if (typeof fixedDelayMs === 'number') return Math.max(0, fixedDelayMs)
    const exp = Math.max(0, attempts - 1)
    const delay = OUTBOX_DEFAULT_BASE_DELAY_MS * Math.pow(2, exp)
    return Math.min(OUTBOX_DEFAULT_MAX_DELAY_MS, Math.max(OUTBOX_DEFAULT_BASE_DELAY_MS, delay))
  }

  function makeClientMsgId() {
    // Browser support is good for crypto.randomUUID; fallback kept defensive.
    try {
      if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID()
    } catch {
      // ignore
    }
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`
  }

  const myId = ref<string | null>(null)
  const myName = ref<string | null>(null)

  const turnConfig = ref<unknown | null>(null)

  const voiceInfo = ref<VoiceInfo | null>(null)

  const status = ref<string>('')
  const users = ref<PresenceUser[]>([])
  const chat = ref<ChatMsg[]>([])

  const techInfo = computed(() => {
    // Ensure this recomputes when locale changes.
    void i18n.global.locale.value

    const voice = voiceInfo.value
    if (!voice || (!voice.turnHost && voice.relayPortsTotal == null)) return ''

    const parts: string[] = []
    if (voice.turnHost) parts.push(String(i18n.global.t('session.turn', { host: voice.turnHost })))

    if (typeof voice.relayPortsUsedEstimate === 'number' && typeof voice.relayPortsTotal === 'number') {
      parts.push(
        String(
          i18n.global.t('session.udpRelayPortsRatio', {
            used: voice.relayPortsUsedEstimate,
            total: voice.relayPortsTotal,
          }),
        ),
      )
    } else if (typeof voice.relayPortsTotal === 'number') {
      parts.push(String(i18n.global.t('session.udpRelayPortsTotal', { total: voice.relayPortsTotal })))
    } else if (typeof voice.relayPortsUsedEstimate === 'number') {
      parts.push(String(i18n.global.t('session.udpRelayPortsUsed', { used: voice.relayPortsUsedEstimate })))
    }

    if (typeof voice.maxConferenceUsersEstimate === 'number') {
      parts.push(String(i18n.global.t('session.estConfMax', { users: voice.maxConferenceUsersEstimate })))
    } else if (typeof voice.capacityCallsEstimate === 'number') {
      parts.push(String(i18n.global.t('session.estCallsMax', { calls: voice.capacityCallsEstimate })))
    }

    return parts.join(' • ')
  })

  const inboundHandlers: Array<(type: string, obj: Record<string, unknown>) => void> = []
  const disconnectHandlers: Array<() => void> = []

  const connected = computed(() => ws.value?.readyState === WebSocket.OPEN)
  const inApp = computed(() => Boolean(myName.value))

  function sendRaw(obj: unknown) {
    if (!ws.value || ws.value.readyState !== WebSocket.OPEN) return
    ws.value.send(JSON.stringify(obj))
  }

  function startOutbox() {
    stopOutbox()
    outboxTimer.value = window.setInterval(() => {
      const sock = ws.value
      if (!sock || sock.readyState !== WebSocket.OPEN) return

      const now = Date.now()
      for (const [cMsgId, entry] of outbox) {
        if (entry.nextAt > now) continue
        if (entry.attempts >= entry.maxAttempts) {
          outbox.delete(cMsgId)

          // Only required UX: show a global popup when server didn't receive chat.
          if (entry.kind === 'chatSend') {
            toast.error(
              String(i18n.global.t('toast.chatSendFailedTitle')),
              String(i18n.global.t('toast.chatSendFailedBody')),
            )
          }
          continue
        }
        try {
          sock.send(entry.json)
        } catch {
          // ignore
        }
        entry.attempts += 1
        entry.nextAt = now + calcOutboxDelayMs(entry.attempts, entry.fixedDelayMs)
      }
    }, 500)
  }

  function stopOutbox() {
    if (outboxTimer.value != null) {
      window.clearInterval(outboxTimer.value)
      outboxTimer.value = null
    }
    outbox.clear()
  }

  function sendReliable(
    obj: Record<string, unknown>,
    opts?: { kind?: string; maxAttempts?: number; fixedDelayMs?: number },
  ) {
    if (!ws.value || ws.value.readyState !== WebSocket.OPEN) return
    const cMsgId = makeClientMsgId()
    const payload = { ...obj, cMsgId }
    const json = JSON.stringify(payload)

    // Immediate send + queue for retry until receipt.
    try {
      ws.value.send(json)
    } catch {
      // ignore
    }
    outbox.set(cMsgId, {
      json,
      attempts: 1,
      nextAt: Date.now() + calcOutboxDelayMs(1, opts?.fixedDelayMs),
      maxAttempts: opts?.maxAttempts ?? OUTBOX_DEFAULT_MAX_ATTEMPTS,
      ...(typeof opts?.fixedDelayMs === 'number' ? { fixedDelayMs: opts.fixedDelayMs } : {}),
      ...(opts?.kind ? { kind: opts.kind } : {}),
    })
  }

  function send(obj: unknown) {
    const o = asObj(obj)
    const type = o ? asString(o.type) : null
    if (type === 'ack' || type === 'ping' || type === 'clientHello' || type === 'signal') {
      sendRaw(obj)
      return
    }

    if (o && type) {
      if (type === 'chatSend') {
        // Messaging policy: attempt each second 5 times, then fail.
        sendReliable(o as Record<string, unknown>, { kind: 'chatSend', maxAttempts: 5, fixedDelayMs: 1000 })
      } else {
        sendReliable(o as Record<string, unknown>)
      }
      return
    }

    sendRaw(obj)
  }

  function ack(msgId: string) {
    if (!msgId) return
    sendRaw({ type: 'ack', msgId })
  }

  function rememberMsgId(msgId: string): boolean {
    if (!msgId) return false
    if (seenMsgIds.has(msgId)) return true
    seenMsgIds.add(msgId)
    seenMsgIdQueue.push(msgId)
    if (seenMsgIdQueue.length > SEEN_MSGIDS_MAX) {
      const old = seenMsgIdQueue.shift()
      if (old) seenMsgIds.delete(old)
    }
    return false
  }

  function stopPing() {
    if (pingTimer.value != null) {
      window.clearInterval(pingTimer.value)
      pingTimer.value = null
    }
  }

  function startPing() {
    stopPing()
    // Keep it modest to avoid noisy traffic; presence also refreshes server-side.
    pingTimer.value = window.setInterval(() => {
      send({ type: 'ping' })
    }, 10000)
  }

  function registerInboundHandler(handler: (type: string, obj: Record<string, unknown>) => void) {
    inboundHandlers.push(handler)
  }

  function registerDisconnectHandler(handler: () => void) {
    disconnectHandlers.push(handler)
  }

  function disconnect() {
    try {
      ws.value?.close()
    } catch {
      // ignore
    }

    stopPing()
    stopOutbox()
    ws.value = null
    myId.value = null
    myName.value = null
    turnConfig.value = null
    users.value = []
    chat.value = []
    status.value = ''

    try {
      ui.goHome()
    } catch {
      // ignore
    }

    for (const h of disconnectHandlers) {
      try {
        h()
      } catch {
        // ignore
      }
    }
  }

  function connect(name: string) {
    const desiredName = name.trim()
    if (!desiredName) {
      status.value = String(i18n.global.t('session.enterName'))
      return
    }

    status.value = String(i18n.global.t('session.connecting'))
    disconnect()

    const sock = new WebSocket(wsUrl())
    ws.value = sock

    sock.addEventListener('open', () => {
      // Feature negotiation (server uses this to enable ack+retry).
      sendRaw({ type: 'clientHello', features: { ack: true } })
      startOutbox()
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

      // Reliable delivery: if msgId is present, ack it; dedupe retries.
      const msgId = asString((obj as InboundMsgAny).msgId)
      if (msgId) {
        ack(msgId)
        const isDup = rememberMsgId(msgId)
        if (isDup) return
      }

      if (type === 'hello') {
        const id = asString(obj.id)
        if (id) myId.value = id

        if ('turn' in obj) {
          turnConfig.value = obj.turn
        }
        return
      }

      if (type === 'receipt') {
        const cMsgId = asString(obj.cMsgId)
        const ok = asBool(obj.ok)
        // ok=false is still a terminal receipt; we stop retrying.
        if (cMsgId && ok !== null) outbox.delete(cMsgId)
        return
      }

      if (type === 'nameResult') {
        const ok = asBool(obj.ok)
        const name = asString(obj.name)
        const reason = asString(obj.reason)
        if (ok && name) {
          myName.value = name
          status.value = ''
          startPing()
        } else {
          status.value =
            reason === 'taken'
              ? String(i18n.global.t('session.nameTaken'))
              : String(i18n.global.t('session.invalidName'))
        }
        return
      }

      if (type === 'presence') {
        users.value = Array.isArray(obj.users) ? (obj.users as PresenceUser[]) : []
        voiceInfo.value = asVoiceInfo(obj.voice)
        return
      }

      if (type === 'pong') {
        // no-op (kept for potential diagnostics later)
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

        // Unread counters (best-effort): bump only for messages not authored by me
        // and not currently in the active chat.
        try {
          if (myName.value && fromName === myName.value) return

          const hasFocus = typeof document.hasFocus === 'function' ? document.hasFocus() : true
          const shouldNotifyForAttention = document.hidden || !hasFocus

          if (!isPrivate) {
            if (!ui.isViewingChat(null)) ui.bumpUnread(null)

            // Notify if the user isn't currently viewing the public chat, or app isn't focused.
            if (shouldNotifyForAttention || !ui.isViewingChat(null)) {
              const preview = text.length > 140 ? `${text.slice(0, 137)}…` : text
              notify(String(i18n.global.t('sidebar.groupChat')), `${fromName}: ${preview}`, {
                tag: 'lrcom-chat-public',
              })
              vibrate([100])
            }
            return
          }

          // For private messages, map to the "other" participant.
          const other = fromName === 'System'
            ? (toName ?? null)
            : (myName.value && fromName === myName.value ? (toName ?? null) : fromName)

          if (!other) return
          if (!ui.isViewingChat(other)) ui.bumpUnread(other)

          // Notify if the user isn't currently viewing this private chat, or app isn't focused.
          if (shouldNotifyForAttention || !ui.isViewingChat(other)) {
            const preview = text.length > 140 ? `${text.slice(0, 137)}…` : text
            notify(other, preview, { tag: `lrcom-chat-${other}` })
            vibrate([100])
          }
        } catch {
          // ignore
        }
        return
      }

      if (type === 'error') {
        const code = asString(obj.code)
        if (code === 'NO_NAME') status.value = String(i18n.global.t('session.enterName'))
      }

      for (const h of inboundHandlers) {
        try {
          h(type, obj)
        } catch {
          // ignore
        }
      }
    })

    sock.addEventListener('close', () => {
      if (myName.value) status.value = String(i18n.global.t('session.disconnected'))
      // keep state; user can reconnect
      stopPing()
      stopOutbox()
    })

    sock.addEventListener('error', () => {
      status.value = String(i18n.global.t('session.connectionError'))
    })
  }

  function sendChat(text: string, toName?: string | null) {
    const t = text.trim()
    if (!t) return
    const target = (toName ?? '').trim()
    send(target ? { type: 'chatSend', text: t, toName: target } : { type: 'chatSend', text: t })
  }

  return {
    ws,
    connected,
    inApp,
    myId,
    myName,
    turnConfig,
    voiceInfo,
    techInfo,
    status,
    users,
    chat,
    connect,
    disconnect,
    sendChat,
    send,
    registerInboundHandler,
    registerDisconnectHandler,
  }
})
