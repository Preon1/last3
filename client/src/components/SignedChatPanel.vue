<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'
import { useToastStore } from '../stores/toast'

const signed = useSignedStore()
const toast = useToastStore()
const { t } = useI18n()

const { activeChatId, messagesByChatId, userId, membersByChatId } = storeToRefs(signed)

const chatInput = ref('')
const chatRootEl = ref<HTMLElement | null>(null)
const chatMessagesEl = ref<HTMLDivElement | null>(null)
const chatInputEl = ref<HTMLTextAreaElement | null>(null)

const messageEls = new Map<string, Element>()
let observer: IntersectionObserver | null = null
const pendingReadIds = new Set<string>()
let flushTimer: number | null = null

function clearFlushTimer() {
  if (flushTimer != null) {
    window.clearTimeout(flushTimer)
    flushTimer = null
  }
}

async function flushReads() {
  clearFlushTimer()
  const cid = activeChatId.value
  if (!cid) return
  if (!pendingReadIds.size) return

  const ids = Array.from(pendingReadIds)
  pendingReadIds.clear()
  await signed.markMessagesRead(cid, ids)
}

function scheduleFlush() {
  if (flushTimer != null) return
  flushTimer = window.setTimeout(() => {
    void flushReads()
  }, 500)
}

function ensureObserver() {
  const root = chatMessagesEl.value
  if (!root) return
  if (observer) return

  observer = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue
        const el = e.target as HTMLElement
        const id = el?.dataset?.msgId
        if (!id) continue
        pendingReadIds.add(id)
        scheduleFlush()
      }
    },
    { root, threshold: 0.6 },
  )

  for (const el of messageEls.values()) {
    try {
      observer.observe(el)
    } catch {
      // ignore
    }
  }
}

function disconnectObserver() {
  clearFlushTimer()
  if (observer) {
    try {
      observer.disconnect()
    } catch {
      // ignore
    }
  }
  observer = null
  pendingReadIds.clear()
}

function setMessageEl(id: string, el: Element | null) {
  if (!id) return
  if (el) {
    messageEls.set(id, el)
    if (observer) {
      try {
        observer.observe(el)
      } catch {
        // ignore
      }
    }
  } else {
    const prev = messageEls.get(id)
    if (prev && observer) {
      try {
        observer.unobserve(prev)
      } catch {
        // ignore
      }
    }
    messageEls.delete(id)
  }
}

const rendered = computed(() => {
  const cid = activeChatId.value
  if (!cid) return []
  return messagesByChatId.value[cid] ?? []
})

const canSend = computed(() => Boolean(activeChatId.value && chatInput.value.trim() && !editBusy.value))

const didInitialScroll = ref(false)

const loadMoreBusy = ref(false)
const loadMoreHasMore = ref(true)
const isPrepending = ref(false)

const editingId = ref<string | null>(null)
const editBusy = ref(false)

const replyingToId = ref<string | null>(null)
const replyingToLabel = ref<string>('')

const msgMenuOpen = ref(false)
const msgMenuX = ref(0)
const msgMenuY = ref(0)
const msgMenuMsg = ref<any | null>(null)
const msgMenuEl = ref<HTMLElement | null>(null)

const msgMenuAnchorX = ref(0)
const msgMenuAnchorY = ref(0)

let longPressTimer: number | null = null
let longPressStartX = 0
let longPressStartY = 0
let longPressMoved = false
let longPressFired = false
let longPressPointerId: number | null = null

let lastTapAtMs = 0
let lastTapMsgId: string | null = null

function clearLongPressTimer() {
  if (longPressTimer != null) {
    window.clearTimeout(longPressTimer)
    longPressTimer = null
  }
}

type LinkPart = { text: string; href?: string }

function isMineMessage(senderId: string) {
  return Boolean(userId.value && senderId === userId.value)
}

function focusChatInputNow() {
  void nextTick(() => {
    try {
      const el = chatInputEl.value
      el?.focus()
      const pos = chatInput.value.length
      el?.setSelectionRange(pos, pos)
    } catch {
      // ignore
    }
  })
}

function startEdit(m: { id: string; text: string; senderId: string }) {
  if (!isMineMessage(String(m.senderId))) return
  if (editBusy.value) return
  if (editingId.value && editingId.value !== String(m.id)) return

  cancelReply()
  editingId.value = String(m.id)
  chatInput.value = String(m.text ?? '')
  queueMicrotask(() => autoGrowChatInput())
  focusChatInputNow()
}

function startReply(m: { id: string; text: string; fromUsername: string; senderId: string }) {
  if (editBusy.value) return
  if (editingId.value) return
  replyingToId.value = m.id
  const cid = activeChatId.value
  const memberName = cid ? membersByChatId.value[cid]?.find((x) => x.userId === m.senderId)?.username : null
  const senderName = memberName || m.fromUsername
  const preview = (m.text ?? '').trim().slice(0, 80)
  replyingToLabel.value = preview ? `${senderName}: ${preview}` : String(senderName)
  focusChatInputNow()
}

function cancelReply() {
  replyingToId.value = null
  replyingToLabel.value = ''
}

function cancelEdit() {
  editingId.value = null
  chatInput.value = ''
  queueMicrotask(() => autoGrowChatInput(true))
}

function closeMsgMenu() {
  msgMenuOpen.value = false
  msgMenuMsg.value = null
}

function onViewportChange() {
  if (!msgMenuOpen.value) return
  void positionMsgMenuNow()
}

function focusChatInputSoon() {
  if (window.innerWidth <= 768) return
  if (!activeChatId.value) return

  window.setTimeout(() => {
    if (window.innerWidth <= 768) return
    if (!activeChatId.value) return
    try {
      chatInputEl.value?.focus()
    } catch {
      // ignore
    }
  }, 50)
}

function normalizeTel(raw: string) {
  const s = String(raw ?? '').trim()
  const hasPlus = s.startsWith('+')
  const digits = s.replace(/\D/g, '')
  if (!digits) return null
  return `${hasPlus ? '+' : ''}${digits}`
}

function linkifyText(raw: string): LinkPart[] {
  const text = String(raw ?? '')
  if (!text) return [{ text: '' }]

  // URL / email / phone
  const re = /(\bhttps?:\/\/[^\s<]+|\bwww\.[^\s<]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\+?\d[\d\s().-]{6,}\d)/g
  const parts: LinkPart[] = []

  let lastIndex = 0
  for (let match = re.exec(text); match; match = re.exec(text)) {
    const idx = match.index ?? 0
    const token = String(match[0] ?? '')

    if (idx > lastIndex) {
      parts.push({ text: text.slice(lastIndex, idx) })
    }

    let href: string | undefined
    const lower = token.toLowerCase()

    if (token.includes('@') && !lower.startsWith('http') && !lower.startsWith('www.')) {
      href = `mailto:${token}`
    } else if (lower.startsWith('http://') || lower.startsWith('https://')) {
      href = token
    } else if (lower.startsWith('www.')) {
      href = `https://${token}`
    } else {
      const tel = normalizeTel(token)
      const digitCount = tel ? tel.replace(/\D/g, '').length : 0
      if (tel && digitCount >= 8) {
        href = `tel:${tel}`
      }
    }

    parts.push(href ? { text: token, href } : { text: token })
    lastIndex = idx + token.length
  }

  if (lastIndex < text.length) {
    parts.push({ text: text.slice(lastIndex) })
  }

  return parts.length ? parts : [{ text }]
}

async function copyText(text: string) {
  const s = String(text ?? '')
  try {
    await navigator.clipboard.writeText(s)
    toast.push({ title: String(t('toast.copiedTitle')), message: String(t('toast.copiedBody')), variant: 'info', timeoutMs: 2000 })
    return
  } catch {
    // ignore, fallback below
  }

  try {
    const ta = document.createElement('textarea')
    ta.value = s
    ta.setAttribute('readonly', 'true')
    ta.style.position = 'fixed'
    ta.style.left = '-9999px'
    ta.style.top = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    if (!ok) throw new Error('execCommand(copy) failed')
    toast.push({ title: String(t('toast.copiedTitle')), message: String(t('toast.copiedBody')), variant: 'info', timeoutMs: 2000 })
  } catch {
    toast.error(String(t('toast.copyFailedTitle')), String(t('toast.copyFailedBody')))
  }
}

function openMsgMenu(e: MouseEvent, m: any) {
  e.preventDefault()
  e.stopPropagation()
  openMsgMenuAt(e.clientX, e.clientY, m)
}

function getViewportMetrics() {
  // On mobile, when the keyboard is open, the visual viewport can be smaller and offset
  // relative to the layout viewport. Our menu is `position: fixed`, so we need to map
  // pointer coordinates (visual viewport) into layout-viewport coordinates.
  const vv = window.visualViewport
  if (vv) {
    return {
      left: vv.offsetLeft || 0,
      top: vv.offsetTop || 0,
      width: vv.width || window.innerWidth,
      height: vv.height || window.innerHeight,
    }
  }
  return { left: 0, top: 0, width: window.innerWidth, height: window.innerHeight }
}

async function positionMsgMenuNow() {
  await nextTick()
  const el = msgMenuEl.value
  if (!el) return

  const r = el.getBoundingClientRect()
  const pad = 8
  const vp = getViewportMetrics()

  // Anchor coordinates are in visual-viewport space (clientX/clientY).
  const baseX = vp.left + msgMenuAnchorX.value
  const baseY = vp.top + msgMenuAnchorY.value

  const minX = vp.left + pad
  const minY = vp.top + pad
  const maxX = Math.max(minX, vp.left + vp.width - r.width - pad)
  const maxY = Math.max(minY, vp.top + vp.height - r.height - pad)

  msgMenuX.value = Math.min(Math.max(baseX, minX), maxX)
  msgMenuY.value = Math.min(Math.max(baseY, minY), maxY)
}

function openMsgMenuAt(x: number, y: number, m: any) {
  msgMenuMsg.value = m
  msgMenuOpen.value = true

  msgMenuAnchorX.value = x
  msgMenuAnchorY.value = y

  // Set an initial position immediately; then clamp precisely after DOM paints.
  const vp = getViewportMetrics()
  msgMenuX.value = vp.left + x
  msgMenuY.value = vp.top + y
  void positionMsgMenuNow()
}

function onMsgPointerDown(e: PointerEvent, m: any) {
  if (e.pointerType !== 'touch') return
  // Prevent the global pointerdown handler from immediately closing the menu.
  e.preventDefault()
  e.stopPropagation()

  clearLongPressTimer()
  longPressFired = false
  longPressMoved = false
  longPressPointerId = e.pointerId
  longPressStartX = e.clientX
  longPressStartY = e.clientY

  // Long-press opens context menu.
  longPressTimer = window.setTimeout(() => {
    if (longPressMoved) return
    longPressFired = true
    openMsgMenuAt(longPressStartX, longPressStartY, m)
    clearLongPressTimer()
  }, 500)
}

function onMsgPointerMove(e: PointerEvent) {
  if (e.pointerType !== 'touch') return
  if (longPressPointerId == null || e.pointerId !== longPressPointerId) return
  const dx = e.clientX - longPressStartX
  const dy = e.clientY - longPressStartY
  if (dx * dx + dy * dy > 10 * 10) {
    longPressMoved = true
    clearLongPressTimer()
  }
}

function onMsgPointerUp(e: PointerEvent, m: any) {
  if (e.pointerType !== 'touch') return
  if (longPressPointerId == null || e.pointerId !== longPressPointerId) return

  clearLongPressTimer()
  longPressPointerId = null

  // If a long-press already opened the menu, don't treat this as a tap.
  if (longPressFired) {
    longPressFired = false
    return
  }

  // Double-tap opens context menu.
  const now = Date.now()
  const id = String(m?.id ?? '')
  if (!id) return

  const isDoubleTap = lastTapMsgId === id && now - lastTapAtMs <= 300
  lastTapAtMs = now
  lastTapMsgId = id

  if (isDoubleTap) {
    // Prevent the second tap from doing any default behaviors.
    e.preventDefault()
    e.stopPropagation()
    lastTapAtMs = 0
    lastTapMsgId = null
    openMsgMenuAt(e.clientX, e.clientY, m)
  }
}

function onMsgPointerCancel(e: PointerEvent) {
  if (e.pointerType !== 'touch') return
  if (longPressPointerId == null || e.pointerId !== longPressPointerId) return
  clearLongPressTimer()
  longPressPointerId = null
}

function onMsgMenuReply() {
  if (!msgMenuMsg.value) return
  startReply(msgMenuMsg.value)
  closeMsgMenu()
}

function onMsgMenuEdit() {
  if (!msgMenuMsg.value) return
  startEdit(msgMenuMsg.value)
  closeMsgMenu()
}

function onMsgMenuDelete() {
  const m = msgMenuMsg.value
  if (!m) return
  void deleteMsg(String(m.chatId), String(m.id), String(m.senderId))
  closeMsgMenu()
}

function onMsgMenuCopy() {
  const m = msgMenuMsg.value
  if (!m) return
  void copyText(String(m.text ?? ''))
  closeMsgMenu()
}

function onGlobalPointerDown(e: PointerEvent) {
  if (!msgMenuOpen.value) return
  const el = msgMenuEl.value
  if (!el) return
  if (!(e.target instanceof Node)) return
  if (el.contains(e.target)) return
  closeMsgMenu()
}

function onGlobalKeyDown(e: KeyboardEvent) {
  if (e.key !== 'Escape') return

  if (msgMenuOpen.value) {
    e.preventDefault()
    closeMsgMenu()
    return
  }

  if (replyingToId.value) {
    e.preventDefault()
    cancelReply()
    return
  }

  if (editingId.value) {
    e.preventDefault()
    cancelEdit()
    return
  }
}

onMounted(() => {
  document.addEventListener('pointerdown', onGlobalPointerDown)
  document.addEventListener('keydown', onGlobalKeyDown)
  try {
    window.visualViewport?.addEventListener('resize', onViewportChange)
    window.visualViewport?.addEventListener('scroll', onViewportChange)
  } catch {
    // ignore
  }
  focusChatInputSoon()
})

function showSendError(e: any) {
  const msg = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
  if (msg === 'Encrypted message too large') {
    toast.error(String(t('toast.chatTooLargeTitle')), String(t('toast.chatTooLargeBody')))
    return
  }
  toast.error(String(t('toast.chatSendFailedTitle')), msg)
}

async function saveEdit(chatId: string, messageId: string) {
  if (!chatId) return
  if (!messageId) return
  const next = chatInput.value.trim()
  if (!next) return
  editBusy.value = true
  try {
    await signed.updateMessageText(chatId, messageId, next)
    editingId.value = null
    chatInput.value = ''
    queueMicrotask(() => autoGrowChatInput(true))
  } catch (e: any) {
    showSendError(e)
  } finally {
    editBusy.value = false
  }
}

async function deleteMsg(chatId: string, messageId: string, senderId: string) {
  if (!isMineMessage(senderId)) return
  if (editBusy.value) return
  if (editingId.value) return
  if (!window.confirm(String(t('confirm.deleteMessage')))) return
  await signed.deleteMessage(chatId, messageId)
  if (editingId.value === messageId) cancelEdit()
}

function scrollToBottom() {
  const root = chatRootEl.value
  const msgs = chatMessagesEl.value

  const scrollToBottomInstant = (el: HTMLElement) => {
    try {
      const prev = el.style.scrollBehavior
      el.style.scrollBehavior = 'auto'
      el.scrollTop = el.scrollHeight
      // Restore after the sync scroll has applied.
      el.style.scrollBehavior = prev
    } catch {
      // ignore
    }
  }

  // Primary: the whole chat section (user-requested scroll container)
  if (root) {
    scrollToBottomInstant(root)
  }

  // Also keep messages scroller aligned if present
  if (msgs) {
    scrollToBottomInstant(msgs)
  }
}

function scrollInitialPosition() {
  scrollToBottom()
}

watch(
  () => rendered.value.length,
  async () => {
    await nextTick()
    ensureObserver()

    if (isPrepending.value) return

    const cid = activeChatId.value
    if (cid && !didInitialScroll.value) {
      didInitialScroll.value = true
      scrollInitialPosition()
      return
    }

    scrollToBottom()
  },
)

watch(
  () => activeChatId.value,
  async () => {
    disconnectObserver()
    closeMsgMenu()
    cancelReply()
    if (editingId.value) cancelEdit()
    didInitialScroll.value = false
    loadMoreHasMore.value = true
    loadMoreBusy.value = false
    isPrepending.value = false
    await nextTick()
    ensureObserver()
    focusChatInputSoon()
  },
)

onBeforeUnmount(() => {
  disconnectObserver()
  document.removeEventListener('pointerdown', onGlobalPointerDown)
  document.removeEventListener('keydown', onGlobalKeyDown)
  try {
    window.visualViewport?.removeEventListener('resize', onViewportChange)
    window.visualViewport?.removeEventListener('scroll', onViewportChange)
  } catch {
    // ignore
  }
})

async function onSend() {
  const cid = activeChatId.value
  if (!cid) return
  const t0 = chatInput.value.trim()
  if (!t0) return

  if (editingId.value) {
    await saveEdit(cid, editingId.value)
    return
  }

  const rid = replyingToId.value
  try {
    await signed.sendMessage(cid, t0, { replyToId: rid })
    chatInput.value = ''
    cancelReply()
    queueMicrotask(() => autoGrowChatInput(true))
  } catch (e: any) {
    showSendError(e)
  }
}

function fmtMessageTime(iso: string) {
  try {
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return ''
    const now = new Date()
    const isToday =
      d.getFullYear() === now.getFullYear() &&
      d.getMonth() === now.getMonth() &&
      d.getDate() === now.getDate()

    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    if (isToday) return time

    const date = d.toLocaleDateString()
    return `${date} ${time}`
  } catch {
    return ''
  }
}

// basic padding bottom of messages container
const messagesContainerPB = ref(63)
const lastTarget = ref(0)

watchEffect(() => {
  const messagesContainer = chatMessagesEl.value
  if (messagesContainer) {
    messagesContainerPB.value = Number.parseFloat(window.getComputedStyle(messagesContainer).paddingBottom)
    || messagesContainerPB.value
  }
})

function autoGrowChatInput(reset = false) {
  const el = chatInputEl.value
  if (!el) return
  const cs = window.getComputedStyle(el)
  const lineHeight = Number.parseFloat(cs.lineHeight) || 20
  const paddingTop = Number.parseFloat(cs.paddingTop) || 0
  const paddingBottom = Number.parseFloat(cs.paddingBottom) || 0

  const basicHeight = Math.ceil(lineHeight + paddingTop + paddingBottom + 2)
  const maxHeight = lineHeight * 8 + paddingTop + paddingBottom + 2
  let target = Math.min(el.scrollHeight + 2, maxHeight)

  if (reset || el.value == '') target = basicHeight

  if (lastTarget.value == 0) lastTarget.value = target

  el.style.height = `${target}px`
  el.style.overflowY = el.scrollHeight + 2 > maxHeight ? 'auto' : 'hidden'

  // increase padding bottom of messages block to correspond with growth of textarea
  const messagesContainer = chatMessagesEl.value
  if (!messagesContainer) return
  messagesContainer.style.paddingBottom = `${messagesContainerPB.value + target - basicHeight}px`

  // scroll messages block to account for textarea height changes
  if (target > lastTarget.value) messagesContainer.scrollBy(0, basicHeight)
  lastTarget.value = target
}

function resolveReplyPreview(replyToId: string) {
  const cid = activeChatId.value
  if (!cid) return ''
  const list = messagesByChatId.value[cid] ?? []
  const found = list.find((x) => x.id === replyToId)
  if (!found) return ''
  const memberName = membersByChatId.value[cid]?.find((x) => x.userId === found.senderId)?.username
  const senderName = memberName || found.fromUsername
  const preview = (found.text ?? '').trim().slice(0, 80)
  return preview ? `${senderName}: ${preview}` : String(senderName)
}


function onChatKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    if (replyingToId.value) {
      e.preventDefault()
      cancelReply()
      return
    }
    if (editingId.value) {
      e.preventDefault()
      cancelEdit()
      return
    }
  }

  if (e.key === 'ArrowUp') {
    if (editBusy.value) return
    if (editingId.value) return
    const cid = activeChatId.value
    if (!cid) return

    const el = chatInputEl.value
    const atTop = Boolean(el && el.selectionStart === 0 && el.selectionEnd === 0)
    const empty = !chatInput.value.trim()
    if (!atTop || !empty) return

    const uid = userId.value
    if (!uid) return
    const list = rendered.value
    for (let i = list.length - 1; i >= 0; i--) {
      const m: any = list[i]
      if (!m) continue
      if (String(m.senderId) !== String(uid)) continue
      if (typeof m.text !== 'string' || !m.text.trim()) continue
      startEdit(m)
      e.preventDefault()
      void nextTick(() => {
        scrollToBottom()
      })
      return
    }
    return
  }

  // UX: Enter inserts a newline; Shift+Enter sends.
  if (e.key === 'Enter' && e.shiftKey) {
    e.preventDefault()
    void onSend()
  }
}


async function tryLoadMore() {
  const cid = activeChatId.value
  const root = chatMessagesEl.value
  if (!cid || !root) return
  if (loadMoreBusy.value) return
  if (!loadMoreHasMore.value) return

  loadMoreBusy.value = true
  isPrepending.value = true
  const prevHeight = root.scrollHeight
  const prevTop = root.scrollTop

  try {
    const r = await signed.loadMoreMessages(cid, 100)
    loadMoreHasMore.value = Boolean(r?.hasMore)
    await nextTick()
    const nextHeight = root.scrollHeight
    const delta = nextHeight - prevHeight
    root.scrollTop = prevTop + delta
  } finally {
    isPrepending.value = false
    loadMoreBusy.value = false
  }
}

function onMessagesScroll() {
  const el = chatMessagesEl.value
  if (!el) return
  if (el.scrollTop < 80) {
    void tryLoadMore()
  }
}

</script>

<template>
  <section ref="chatRootEl" class="chat">

    <div ref="chatMessagesEl" class="chat-messages" aria-live="polite" @scroll="onMessagesScroll">
      <div
        v-for="m in rendered"
        :key="m.id"
        class="chat-line"
        :class="{
          'chat-line--reply-target': replyingToId === m.id,
          'chat-line--edit-target': editingId === m.id,
          'chat-line--menu-target': msgMenuOpen && msgMenuMsg && String(msgMenuMsg.id) === String(m.id),
        }"
        :ref="(el) => setMessageEl(m.id, el as any)"
        :data-msg-id="m.id"
        @contextmenu.prevent="openMsgMenu($event, m)"
        @pointerdown="onMsgPointerDown($event, m)"
        @pointermove="onMsgPointerMove"
        @pointerup="onMsgPointerUp($event, m)"
        @pointercancel="onMsgPointerCancel"
      >
        <div class="chat-meta">
          <span>{{ m.fromUsername }}</span>

          <span class="muted" style="margin-left: 10px;">
            <template v-if="m.modifiedAtIso">
              {{ t('common.modified') }} {{ fmtMessageTime(String(m.modifiedAtIso)) }}
            </template>
            <template v-else>
              {{ fmtMessageTime(m.atIso) }}
            </template>
          </span>
        </div>

        <div v-if="m.replyToId" class="muted" style="margin-top: 4px; font-size: 12px;">
          {{ t('chat.replying') }}: {{ resolveReplyPreview(String(m.replyToId)) || String(m.replyToId) }}
        </div>

        <div class="chat-text">
          <template v-for="(p, i) in linkifyText(String(m.text ?? ''))" :key="i">
            <a
              v-if="p.href"
              class="chat-link"
              :href="p.href"
              target="_blank"
              rel="noopener noreferrer"
            >{{ p.text }}</a>
            <span v-else>{{ p.text }}</span>
          </template>
        </div>
      </div>
    </div>

    <div
      v-if="msgMenuOpen && msgMenuMsg"
      ref="msgMenuEl"
      class="msg-menu"
      role="menu"
      :style="{ left: msgMenuX + 'px', top: msgMenuY + 'px' }"
    >
      <button
        class="secondary msg-menu-item"
        type="button"
        role="menuitem"
        :disabled="editBusy || editingId !== null"
        @click="onMsgMenuReply"
      >
        {{ t('common.reply') }}
      </button>

      <button
        class="secondary msg-menu-item"
        type="button"
        role="menuitem"
        :disabled="!isMineMessage(String(msgMenuMsg.senderId)) || editBusy || (editingId !== null && editingId !== String(msgMenuMsg.id))"
        @click="onMsgMenuEdit"
      >
        {{ t('common.edit') }}
      </button>

      <button
        class="secondary msg-menu-item"
        type="button"
        role="menuitem"
        @click="onMsgMenuCopy"
      >
        {{ t('common.copy') }}
      </button>

      <button
        class="secondary msg-menu-item"
        type="button"
        role="menuitem"
        :disabled="!isMineMessage(String(msgMenuMsg.senderId)) || editBusy || editingId !== null"
        @click="onMsgMenuDelete"
      >
        {{ t('common.delete') }}
      </button>
    </div>

    <div class="chat-input">
      <div v-if="replyingToId || editingId" class="muted">
        <button
          class="secondary icon-only small"
          type="button"
          :disabled="Boolean(editBusy && editingId)"
          :aria-label="String(t('common.cancel'))"
          @click="editingId ? cancelEdit() : cancelReply()"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#x"></use></svg>
        </button>
      </div>
      <textarea
        ref="chatInputEl"
        v-model="chatInput"
        :disabled="!activeChatId"
        rows="1"
        autocomplete="off"
        :placeholder="String(t('chat.typeMessage'))"
        @keydown="onChatKeydown"
        @input="autoGrowChatInput()"
      ></textarea>
      <button class="icon-only chat-send" type="button" :disabled="!canSend" :aria-label="String(t('chat.sendAria'))" @click="onSend">
        <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#send"></use></svg>
      </button>
    </div>
  </section>
</template>

<style scoped>
.small{
  padding: 8px;
}
</style>