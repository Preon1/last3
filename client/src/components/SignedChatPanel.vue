<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'

const signed = useSignedStore()
const { t } = useI18n()

const { activeChatId, messagesByChatId, chats, userId, membersByChatId } = storeToRefs(signed)

const chatInput = ref('')
const chatMessagesEl = ref<HTMLDivElement | null>(null)

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

const memberUsername = ref('')
const memberBusy = ref(false)
const memberErr = ref('')

const activeChat = computed(() => {
  const cid = activeChatId.value
  if (!cid) return null
  return chats.value.find((c) => c.id === cid) ?? null
})

const isGroup = computed(() => Boolean(activeChat.value?.type === 'group'))

const rendered = computed(() => {
  const cid = activeChatId.value
  if (!cid) return []
  return messagesByChatId.value[cid] ?? []
})

const canSend = computed(() => Boolean(activeChatId.value && chatInput.value.trim()))

const didInitialScroll = ref(false)

const loadMoreBusy = ref(false)
const loadMoreHasMore = ref(true)
const isPrepending = ref(false)

const editingId = ref<string | null>(null)
const editingText = ref<string>('')
const editBusy = ref(false)

const replyingToId = ref<string | null>(null)
const replyingToLabel = ref<string>('')

function isMineMessage(senderId: string) {
  return Boolean(userId.value && senderId === userId.value)
}

function startEdit(m: { id: string; text: string; senderId: string }) {
  if (!isMineMessage(m.senderId)) return
  if (editBusy.value) return
  if (editingId.value && editingId.value !== m.id) return
  editingId.value = m.id
  editingText.value = m.text
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
}

function cancelReply() {
  replyingToId.value = null
  replyingToLabel.value = ''
}

function cancelEdit() {
  editingId.value = null
  editingText.value = ''
}

async function saveEdit(chatId: string, messageId: string) {
  if (!chatId) return
  if (!messageId) return
  const next = editingText.value.trim()
  if (!next) return
  editBusy.value = true
  try {
    await signed.updateMessageText(chatId, messageId, next)
    cancelEdit()
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
  const el = chatMessagesEl.value
  if (!el) return
  el.scrollTop = el.scrollHeight
}

function cssEscape(s: string) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const css = (window as any).CSS
  return css && typeof css.escape === 'function' ? css.escape(s) : s.replace(/"/g, '\\"')
}

function scrollToMessage(id: string) {
  const root = chatMessagesEl.value
  if (!root) return
  const sel = `[data-msg-id="${cssEscape(id)}"]`
  const el = root.querySelector(sel) as HTMLElement | null
  if (!el) return
  el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  el.classList.add('flash')
  window.setTimeout(() => el.classList.remove('flash'), 900)
}

async function scrollInitialPosition(chatId: string) {
  try {
    const unread = await signed.listUnreadMessageIds(chatId, 500)
    if (!unread.length) {
      scrollToBottom()
      return
    }

    const set = new Set<string>(unread.map(String))
    const first = rendered.value.find((m) => set.has(m.id))
    if (first?.id) {
      scrollToMessage(first.id)
      return
    }
  } catch {
    // ignore
  }
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
      await scrollInitialPosition(cid)
      return
    }

    scrollToBottom()
  },
)

watch(
  () => activeChatId.value,
  async () => {
    disconnectObserver()
    didInitialScroll.value = false
    loadMoreHasMore.value = true
    loadMoreBusy.value = false
    isPrepending.value = false
    await nextTick()
    ensureObserver()
  },
)

onBeforeUnmount(() => {
  disconnectObserver()
})

async function onSend() {
  const cid = activeChatId.value
  if (!cid) return
  const t0 = chatInput.value.trim()
  if (!t0) return
  chatInput.value = ''
  const rid = replyingToId.value
  cancelReply()
  await signed.sendMessage(cid, t0, { replyToId: rid })
}

function fmtIso(iso: string) {
  try {
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return ''
    return d.toLocaleString()
  } catch {
    return ''
  }
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

async function onAddMember() {
  memberErr.value = ''
  const cid = activeChatId.value
  if (!cid) return
  const u = memberUsername.value.trim()
  if (!u) return
  memberBusy.value = true
  try {
    await signed.addGroupMember(cid, u)
    memberUsername.value = ''
  } catch (e: any) {
    memberErr.value = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
  } finally {
    memberBusy.value = false
  }
}

function onChatKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
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
  <section class="chat">
    <div v-if="isGroup" class="chat-input" style="padding-bottom: 8px;">
      <input
        v-model="memberUsername"
        :disabled="memberBusy || !activeChatId"
        maxlength="64"
        autocomplete="off"
        :placeholder="String(t('signed.memberPlaceholder'))"
        @keydown.enter.prevent="onAddMember"
      />
      <button class="secondary" type="button" :disabled="memberBusy || !memberUsername.trim()" @click="onAddMember">
        {{ t('signed.addMember') }}
      </button>
    </div>

    <div v-if="memberErr" class="status" aria-live="polite" style="margin: 0 12px 8px;">{{ memberErr }}</div>

    <div ref="chatMessagesEl" class="chat-messages" aria-live="polite" @scroll="onMessagesScroll">
      <div v-for="m in rendered" :key="m.id" class="chat-line" :ref="(el) => setMessageEl(m.id, el as any)" :data-msg-id="m.id">
        <div class="chat-meta">
          <span>{{ m.fromUsername }}</span>

          <span class="muted" style="margin-left: 10px;">
            <template v-if="m.modifiedAtIso">
              {{ t('common.modified') }} {{ fmtIso(String(m.modifiedAtIso)) }}
            </template>
            <template v-else>
              {{ fmtIso(m.atIso) }}
            </template>
          </span>

          <div
            v-if="isMineMessage(m.senderId) && editingId !== m.id"
            style="margin-left: auto; display: flex; gap: 8px; align-items: center;"
          >
            <button
              class="reply-btn"
              type="button"
              style="margin-left: 0;"
              :disabled="editBusy || editingId !== null"
              @click="startReply(m)"
            >
              {{ t('common.reply') }}
            </button>
            <button
              class="reply-btn"
              type="button"
              style="margin-left: 0;"
              :disabled="editBusy || (editingId !== null && editingId !== m.id)"
              @click="startEdit(m)"
            >
              {{ t('common.edit') }}
            </button>
            <button
              class="reply-btn"
              type="button"
              style="margin-left: 0;"
              :disabled="editBusy || editingId !== null"
              @click="deleteMsg(m.chatId, m.id, m.senderId)"
            >
              {{ t('common.delete') }}
            </button>
          </div>

          <div v-else style="margin-left: auto; display: flex; gap: 8px; align-items: center;">
            <button
              class="reply-btn"
              type="button"
              style="margin-left: 0;"
              :disabled="editBusy || editingId !== null"
              @click="startReply(m)"
            >
              {{ t('common.reply') }}
            </button>
          </div>
        </div>

        <div v-if="m.replyToId" class="muted" style="margin-top: 4px; font-size: 12px;">
          {{ t('chat.replying') }}: {{ resolveReplyPreview(String(m.replyToId)) || String(m.replyToId) }}
        </div>

        <div v-if="editingId === m.id" class="chat-text">
          <textarea
            v-model="editingText"
            rows="2"
            maxlength="500"
            autocomplete="off"
            style="width: 100%; margin-top: 6px;"
          ></textarea>
          <div style="display: flex; gap: 8px; margin-top: 6px;">
            <button class="secondary" type="button" :disabled="editBusy" @click="cancelEdit">{{ t('common.cancel') }}</button>
            <button type="button" :disabled="editBusy || !editingText.trim()" @click="saveEdit(m.chatId, m.id)">{{ t('common.save') }}</button>
          </div>
        </div>
        <div v-else class="chat-text">{{ m.text }}</div>
      </div>
    </div>

    <div class="chat-input">
      <div v-if="replyingToId" class="muted" style="margin: 0 0 6px; display: flex; justify-content: space-between; gap: 12px;">
        <span>{{ t('chat.replying') }}: {{ replyingToLabel }}</span>
        <button class="secondary" type="button" @click="cancelReply">{{ t('common.cancel') }}</button>
      </div>
      <textarea
        v-model="chatInput"
        :disabled="!activeChatId"
        rows="1"
        maxlength="500"
        autocomplete="off"
        :placeholder="String(t('chat.typeMessage'))"
        @keydown="onChatKeydown"
      ></textarea>
      <button class="icon-only chat-send" type="button" :disabled="!canSend" :aria-label="String(t('chat.sendAria'))" @click="onSend">
        <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#send"></use></svg>
      </button>
    </div>
  </section>
</template>
