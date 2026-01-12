<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'
import { useCallStore } from '../stores/call'

const signed = useSignedStore()
const call = useCallStore()
const { view, otherChatsUnread, activeChatId, chats } = storeToRefs(signed)
const { joinConfirmToId, joinConfirmToName, inCall, outgoingPending, pendingIncomingFrom, joinPending } = storeToRefs(call)
const { t } = useI18n()

const otherMenuOpen = ref(false)
const otherMenuRoot = ref<HTMLElement | null>(null)
const otherMenuButton = ref<HTMLButtonElement | null>(null)

const activeChat = computed(() => {
  const cid = activeChatId.value
  if (!cid) return null
  return chats.value.find((c) => c.id === cid) ?? null
})

const chatOnlineState = computed(() => {
  const cid = activeChatId.value
  if (!cid) return null
  return signed.getChatOnlineState(cid)
})

const chatTitle = computed(() => {
  if (view.value !== 'chat') return String(t('common.settings'))
  const c = activeChat.value
  if (!c) return String(t('signed.chat'))
  return c.type === 'personal' ? String(c.otherUsername ?? c.id) : String(c.name ?? c.id)
})

const canCall = computed(() => {
  if (view.value !== 'chat') return false
  const c = activeChat.value
  if (!c || c.type !== 'personal') return false
  if (!c.otherUserId || !c.otherUsername) return false
  if (pendingIncomingFrom.value) return false
  if (outgoingPending.value) return false
  if (inCall.value) return false
  if (joinPending.value) return false
  return true
})

const canDeleteChat = computed(() => {
  if (view.value !== 'chat') return false
  if (!activeChatId.value) return false
  if (inCall.value) return false
  if (outgoingPending.value) return false
  if (pendingIncomingFrom.value) return false
  if (joinPending.value) return false
  return true
})

function onDeleteChat() {
  const cid = activeChatId.value
  if (!cid) return
  const isGroup = activeChat.value?.type === 'group'
  const ok = window.confirm(String(isGroup ? t('confirm.leaveGroup') : t('confirm.deleteChat')))
  if (!ok) return
  otherMenuOpen.value = false
  void signed.deleteChat(cid)
}

function onCall() {
  const c = activeChat.value
  if (!c || c.type !== 'personal') return
  if (!c.otherUserId || !c.otherUsername) return
  void call.startCall(c.otherUserId, c.otherUsername)
}

function toggleOtherMenu() {
  otherMenuOpen.value = !otherMenuOpen.value
}

function closeOtherMenu() {
  otherMenuOpen.value = false
}

function onGlobalPointerDown(e: PointerEvent) {
  if (!otherMenuOpen.value) return
  const root = otherMenuRoot.value
  if (!root) return
  if (!(e.target instanceof Node)) return
  if (root.contains(e.target)) return
  closeOtherMenu()
}

function onGlobalKeyDown(e: KeyboardEvent) {
  if (!otherMenuOpen.value) return
  if (e.key !== 'Escape') return
  e.preventDefault()
  closeOtherMenu()
  otherMenuButton.value?.focus()
}

onMounted(() => {
  document.addEventListener('pointerdown', onGlobalPointerDown)
  document.addEventListener('keydown', onGlobalKeyDown)
})

onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onGlobalPointerDown)
  document.removeEventListener('keydown', onGlobalKeyDown)
})

watch([view, activeChatId], () => closeOtherMenu())
</script>

<template>
  <div class="floating-header" v-if="view !== 'contacts'">
    <button class="secondary icon-only" type="button" :aria-label="String(t('common.back'))" @click="signed.goHome">
      <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#bracket-left"></use></svg>
    </button>

    <div
      v-if="view === 'chat' && otherChatsUnread > 0"
      class="floating-unread-badge"
      :aria-label="String(t('common.unreadMessages'))"
    >
      {{ otherChatsUnread }}
    </div>

    <div class="page-info">
      <div class="page-info-title">{{ chatTitle }}</div>
      <span
        v-if="view === 'chat' && chatOnlineState !== null"
        class="status-dot"
        :class="{ online: chatOnlineState === 'online', offline: chatOnlineState === 'offline', busy: chatOnlineState === 'busy' }"
        aria-hidden="true"
      />
    </div>

    <div v-if="view === 'chat'" class="page-actions">
      <button
        v-if="activeChat?.type === 'personal'"
        class="secondary icon-only"
        type="button"
        :aria-label="String(t('chat.callAria'))"
        :disabled="!canCall"
        @click="onCall"
      >
        <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#call"></use></svg>
      </button>

      <div class="page-other-actions" ref="otherMenuRoot">
        <button
          ref="otherMenuButton"
          class="secondary icon-only"
          type="button"
          aria-haspopup="menu"
          :aria-expanded="otherMenuOpen ? 'true' : 'false'"
          :disabled="!canDeleteChat"
          @click="toggleOtherMenu"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#dots-vertical"></use></svg>
        </button>

        <div v-if="otherMenuOpen" class="page-other-menu" role="menu">
          <button
            class="secondary page-other-item"
            type="button"
            role="menuitem"
            :disabled="!canDeleteChat"
            @click="onDeleteChat"
          >
            {{ activeChat?.type === 'group' ? t('signed.leaveGroup') : t('signed.deleteChat') }}
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="joinConfirmToId"
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="joinConfirmTitleSigned"
      @click="(e) => { if (e.target === e.currentTarget) call.cancelJoinConfirm() }"
    >
      <div class="modal-card">
        <div class="modal-title" id="joinConfirmTitleSigned">{{ t('chat.joinOngoingTitle') }}</div>
        <div class="muted" style="margin-bottom: 12px;">
          {{ joinConfirmToName ? t('chat.joinOngoingBodyNamed', { name: joinConfirmToName }) : t('chat.joinOngoingBody') }}
        </div>
        <div class="modal-actions">
          <button class="secondary" type="button" @click="call.cancelJoinConfirm">{{ t('common.cancel') }}</button>
          <button type="button" @click="call.confirmJoinAttempt">{{ t('common.proceed') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>
