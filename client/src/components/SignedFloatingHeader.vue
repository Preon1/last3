<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'
import { useCallStore } from '../stores/call'

const signed = useSignedStore()
const call = useCallStore()
const { view, otherChatsUnread, activeChatId, chats, membersByChatId } = storeToRefs(signed)
const { joinConfirmToId, joinConfirmToName, inCall, outgoingPending, pendingIncomingFrom, joinPending } = storeToRefs(call)
const { t } = useI18n()

const otherMenuOpen = ref(false)
const otherMenuRoot = ref<HTMLElement | null>(null)
const otherMenuButton = ref<HTMLButtonElement | null>(null)

const addMemberOpen = ref(false)
const addMemberUsername = ref('')
const addMemberBusy = ref(false)
const addMemberReport = ref('')

const membersOpen = ref(false)
const membersBusy = ref(false)
const membersErr = ref('')

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

const groupMembers = computed(() => {
  const cid = activeChatId.value
  if (!cid) return []
  return membersByChatId.value[cid] ?? []
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

const canOpenOtherMenu = computed(() => {
  if (view.value !== 'chat') return false
  if (!activeChatId.value) return false
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

function openMembersList() {
  membersErr.value = ''
  const cid = activeChatId.value
  if (!cid) return
  closeOtherMenu()
  membersOpen.value = true
  membersBusy.value = true
  void (async () => {
    try {
      await signed.fetchChatMembers(cid)
    } catch (e: any) {
      membersErr.value = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
    } finally {
      membersBusy.value = false
    }
  })()
}

function closeMembersList() {
  membersOpen.value = false
  membersBusy.value = false
  membersErr.value = ''
}

function openAddMember() {
  closeOtherMenu()
  addMemberOpen.value = true
  addMemberReport.value = ''
  void nextTick(() => {
    try {
      const el = document.getElementById('addMemberUsername') as HTMLInputElement | null
      el?.focus()
    } catch {
      // ignore
    }
  })
}

function closeAddMember() {
  addMemberOpen.value = false
  addMemberBusy.value = false
  addMemberReport.value = ''
}

async function onAddMember() {
  addMemberReport.value = ''
  const cid = activeChatId.value
  if (!cid) return
  const u = addMemberUsername.value.trim()
  if (!u) return
  addMemberBusy.value = true
  try {
    await signed.addGroupMember(cid, u)
    addMemberReport.value = String(t('signed.memberAddedOk'))
    addMemberUsername.value = ''
  } catch (e: any) {
    const msg = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
    const isIntrovert = msg === 'introvert' || msg.toLowerCase().includes('introvert mode')
    if (isIntrovert) {
      addMemberReport.value = msg === 'introvert' ? String(t('toast.introvertBody')) : msg
      return
    }
    addMemberReport.value = msg
  } finally {
    addMemberBusy.value = false
  }
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
  if (e.key !== 'Escape') return
  if (addMemberOpen.value) {
    e.preventDefault()
    closeAddMember()
    return
  }
  if (membersOpen.value) {
    e.preventDefault()
    closeMembersList()
    return
  }
  if (otherMenuOpen.value) {
    e.preventDefault()
    closeOtherMenu()
    otherMenuButton.value?.focus()
  }
}

onMounted(() => {
  document.addEventListener('pointerdown', onGlobalPointerDown)
  document.addEventListener('keydown', onGlobalKeyDown)
})

onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onGlobalPointerDown)
  document.removeEventListener('keydown', onGlobalKeyDown)
})

watch([view, activeChatId], () => {
  closeOtherMenu()
  closeAddMember()
  closeMembersList()
})
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
        v-if="view === 'chat' && activeChat?.type === 'personal' && chatOnlineState !== null"
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
          :disabled="!canOpenOtherMenu"
          @click="toggleOtherMenu"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#dots-vertical"></use></svg>
        </button>

        <div v-if="otherMenuOpen" class="page-other-menu" role="menu">
          <button
            v-if="activeChat?.type === 'group'"
            class="secondary page-other-item"
            type="button"
            role="menuitem"
            @click="openMembersList"
          >
            {{ t('signed.membersList') }}
          </button>

          <button
            v-if="activeChat?.type === 'group'"
            class="secondary page-other-item"
            type="button"
            role="menuitem"
            :disabled="addMemberBusy"
            @click="openAddMember"
          >
            {{ t('signed.addMember') }}
          </button>

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
      v-if="membersOpen"
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="membersListTitleSigned"
      @click="(e) => { if (e.target === e.currentTarget) closeMembersList() }"
    >
      <div class="modal-card">
        <div class="modal-title" id="membersListTitleSigned">{{ t('signed.membersList') }}</div>

        <div v-if="membersErr" class="status" aria-live="polite" style="margin-top: 8px;">{{ membersErr }}</div>
        <div v-else-if="membersBusy" class="muted" style="margin-top: 8px;">{{ t('signed.membersLoading') }}</div>

        <div v-else style="margin-top: 8px;">
          <div v-if="groupMembers.length === 0" class="muted">{{ t('signed.noMembers') }}</div>
          <ul v-else style="margin: 0; padding-left: 18px; display: grid; gap: 6px;">
            <li v-for="m in groupMembers" :key="m.userId">{{ m.username }}</li>
          </ul>
        </div>

        <div class="modal-actions">
          <button class="secondary" type="button" @click="closeMembersList">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>

    <div
      v-if="addMemberOpen"
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="addMemberTitleSigned"
      @click="(e) => { if (e.target === e.currentTarget) closeAddMember() }"
    >
      <div class="modal-card">
        <div class="modal-title" id="addMemberTitleSigned">{{ t('signed.addMember') }}</div>

        <div class="field" style="margin-top: 8px;">
          <input
            id="addMemberUsername"
            v-model="addMemberUsername"
            :disabled="addMemberBusy || !activeChatId"
            maxlength="64"
            autocomplete="off"
            :placeholder="String(t('signed.memberPlaceholder'))"
            @keydown.enter.prevent="onAddMember"
          />
          <div v-if="addMemberReport" class="status" aria-live="polite">{{ addMemberReport }}</div>
        </div>

        <div class="modal-actions">
          <button class="secondary" type="button" :disabled="addMemberBusy" @click="closeAddMember">{{ t('common.close') }}</button>
          <button type="button" :disabled="addMemberBusy || !addMemberUsername.trim()" @click="onAddMember">{{ t('signed.addMember') }}</button>
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
