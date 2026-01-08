<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useSessionStore } from '../stores/session'
import { useUiStore } from '../stores/ui'
import { useI18n } from 'vue-i18n'

const session = useSessionStore()
const ui = useUiStore()

const { t } = useI18n()

const { chat, users } = storeToRefs(session)
const { replyToId, activeChatName } = storeToRefs(ui)

// Auto-focus textarea on desktop when chat opens
watchEffect(() => {
  void activeChatName.value
  queueMicrotask(() => {
    if (chatInputEl.value && window.innerWidth > 768) {
      chatInputEl.value.focus()
    }
  })
})

// Call button + join confirm are handled by ChatTopBar, and the call panel is mounted globally.

const chatInput = ref('')
const chatMessagesEl = ref<HTMLElement | null>(null)
const chatInputEl = ref<HTMLTextAreaElement | null>(null)

const filteredChat = computed(() => {
  const peer = activeChatName.value
  // Group chat view
  if (!peer) return chat.value.filter((m) => !m.private)

  // Private chat view with selected user
  return chat.value.filter((m) => m.private && (m.fromName === peer || m.toName === peer))
})

const canSend = computed(() => {
  const peer = activeChatName.value
  // Group chat is always sendable.
  if (!peer) return true

  // Private chat is only sendable if the user is currently online.
  return users.value.some((u) => u.name === peer)
})

function parseReply(text: string): { replyTo: string | null; body: string } {
  if (!text.startsWith('@reply ')) return { replyTo: null, body: text }
  const nl = text.indexOf('\n')
  if (nl <= 7) return { replyTo: null, body: text }
  const id = text.slice(7, nl).trim()
  if (!id) return { replyTo: null, body: text }
  return { replyTo: id, body: text.slice(nl + 1) }
}

const byId = computed(() => {
  const map = new Map<string, { fromName: string; text: string }>()
  for (const m of chat.value) {
    if (m.id) map.set(m.id, { fromName: m.fromName, text: m.text })
  }
  return map
})

const renderedChat = computed(() => {
  return filteredChat.value.map((m) => {
    const parsed = parseReply(m.text)
    return {
      ...m,
      displayText: parsed.body,
      replyTo: parsed.replyTo,
    }
  })
})

const replyBanner = computed(() => {
  if (!replyToId.value) return null
  const found = byId.value.get(replyToId.value)
  if (!found) return { title: String(t('chat.replying')), subtitle: '' }
  const body = parseReply(found.text).body
  const snip = body.length > 80 ? `${body.slice(0, 80)}…` : body
  return { title: String(t('chat.replyingTo', { name: found.fromName })), subtitle: snip }
})

function onSend() {
  if (!canSend.value) return
  const body = chatInput.value.trim()
  if (!body) return
  const text = replyToId.value ? `@reply ${replyToId.value}\n${body}` : body
  session.sendChat(text, activeChatName.value)
  chatInput.value = ''
  if (replyToId.value) ui.clearReply()

  queueMicrotask(() => autoGrowChatInput(true))
}

function isMobileTextEntry() {
  return (navigator.maxTouchPoints ?? 0) > 0 || (window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
}

const messagesContainerPB = ref(53)

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

  if (reset) {
    target = basicHeight
  }

  el.style.height = `${target}px`
  el.style.overflowY = el.scrollHeight + 2 > maxHeight ? 'auto' : 'hidden'

  // increase padding bottom of messages block to correspond with growth of textarea
  const messagesContainer = chatMessagesEl.value
  if (!messagesContainer) return
  messagesContainer.style.paddingBottom = `${messagesContainerPB.value + target - basicHeight}px`
}

function onChatKeydown(e: KeyboardEvent) {
  if (e.key !== 'Enter') return

  // Mobile: Enter inserts newline; send is only via the Send button.
  if (isMobileTextEntry()) return

  // Desktop: Shift+Enter inserts newline.
  if (e.shiftKey) return

  e.preventDefault()
  onSend()
}

watchEffect(() => {
  void filteredChat.value.length
  queueMicrotask(() => {
    if (chatMessagesEl.value) {
      chatMessagesEl.value.scrollTop = chatMessagesEl.value.scrollHeight
    }
  })
})

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

function onClickReplyTarget(id: string) {
  ui.setReplyTo(id)
  queueMicrotask(() => chatInputEl.value?.focus())
}

</script>

<template>
  <section class="chat">
    <div ref="chatMessagesEl" class="chat-messages" aria-live="polite">
      <div
        v-for="(m, i) in renderedChat"
        :key="m.id ?? i"
        class="chat-line"
        :data-msg-id="m.id || undefined"
      >
        <div class="chat-meta">
          <span>{{ m.fromName }}</span>
          <button v-if="m.id" class="reply-btn" type="button" @click="onClickReplyTarget(m.id)">{{ t('common.reply') }}</button>
        </div>
        <button
          v-if="m.replyTo"
          class="reply-ref"
          type="button"
          @click="scrollToMessage(m.replyTo)"
        >
          <template v-if="byId.get(m.replyTo)">
            {{ t('chat.replyTo', { name: byId.get(m.replyTo)!.fromName }) }}
          </template>
          <template v-else>
            {{ t('common.reply') }}
          </template>
        </button>
        <div class="chat-text">{{ m.displayText }}</div>
      </div>
    </div>

    <div v-if="replyBanner" class="reply-banner">
      <div class="reply-banner-text">
        <div class="reply-banner-title">{{ replyBanner.title }}</div>
        <div v-if="replyBanner.subtitle" class="reply-banner-subtitle">{{ replyBanner.subtitle }}</div>
      </div>
      <button class="secondary reply-cancel" type="button" @click="ui.clearReply">{{ t('common.cancel') }}</button>
    </div>

    <div class="chat-input">
      <textarea
        ref="chatInputEl"
        v-model="chatInput"
        :disabled="!canSend"
        rows="1"
        maxlength="500"
        autocomplete="off"
        :placeholder="String(t('chat.typeMessage'))"
        @keydown="onChatKeydown"
        @input="autoGrowChatInput()"
        ></textarea>
        <button
          class="icon-only chat-send"
          type="button"
          :disabled="!canSend"
          :aria-label="String(t('chat.sendAria'))"
          @click="onSend"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#send"></use></svg>
        </button>
      </div>

  </section>
</template>
