<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'
import { useCallStore } from '../stores/call'

const signed = useSignedStore()
const call = useCallStore()
const { view, otherChatsUnread, activeChatId, chats } = storeToRefs(signed)
const { joinConfirmToId, joinConfirmToName, inCall, outgoingPending, pendingIncomingFrom, joinPending } = storeToRefs(call)
const { t } = useI18n()

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
  void signed.deleteChat(cid)
}

function onCall() {
  const c = activeChat.value
  if (!c || c.type !== 'personal') return
  if (!c.otherUserId || !c.otherUsername) return
  void call.startCall(c.otherUserId, c.otherUsername)
}
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

    <div class="chat-topbar" v-if="view === 'chat'">
      <div class="chat-topbar-left">
        <div class="chat-topbar-title">{{ t('signed.chat') }}</div>
        <span
          v-if="chatOnlineState !== null"
          class="status-dot"
          :class="{ online: chatOnlineState === 'online', offline: chatOnlineState === 'offline', busy: chatOnlineState === 'busy' }"
          aria-hidden="true"
        />
      </div>

      <button
        v-if="activeChat?.type === 'personal'"
        class="chat-callbtn secondary icon-only"
        type="button"
        :aria-label="String(t('chat.callAria'))"
        :disabled="!canCall"
        @click="onCall"
      >
        <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#call"></use></svg>
      </button>

      <button
        class="secondary"
        type="button"
        :disabled="!canDeleteChat"
        @click="onDeleteChat"
      >
        {{ activeChat?.type === 'group' ? t('signed.leaveGroup') : t('signed.deleteChat') }}
      </button>

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

    <div class="chat-topbar" v-else>
      <div class="chat-topbar-left">
        <div class="chat-topbar-title">{{ t('common.settings') }}</div>
      </div>
    </div>
  </div>
</template>
