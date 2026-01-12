<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useSignedStore } from '../stores/signed'
import { useI18n } from 'vue-i18n'
import { useToastStore } from '../stores/toast'

const signed = useSignedStore()
const toast = useToastStore()
const { t } = useI18n()

const { chats, unreadByChatId, activeChatId } = storeToRefs(signed)

const friend = ref('')
const groupName = ref('')
const showAddModal = ref(false)
const busy = ref(false)
const err = ref<string>('')

const sortedChats = computed(() => chats.value.slice())

function isActive(id: string) {
  return (activeChatId.value ?? null) === id
}

async function onAddFriend() {
  err.value = ''
  const u = friend.value.trim()
  if (!u) return
  busy.value = true
  try {
    await signed.createPersonalChat(u)
    friend.value = ''
  } catch (e: any) {
    const msg = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
    const isIntrovert = msg === 'introvert' || msg.toLowerCase().includes('introvert mode')
    if (isIntrovert) {
      toast.error(String(t('toast.introvertTitle')), msg === 'introvert' ? String(t('toast.introvertBody')) : msg)
      return
    }
    err.value = msg
  } finally {
    busy.value = false
  }
}

async function onCreateGroup() {
  err.value = ''
  const n = groupName.value.trim()
  if (!n) return
  busy.value = true
  try {
    await signed.createGroupChat(n)
    groupName.value = ''
  } catch (e: any) {
    err.value = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
  } finally {
    busy.value = false
  }
}

async function onOpen(chatId: string) {
  err.value = ''
  busy.value = true
  try {
    await signed.openChat(chatId)
  } catch (e: any) {
    err.value = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
  } finally {
    busy.value = false
  }
}

function openAdd() {
  err.value = ''
  showAddModal.value = true
}

function closeAdd() {
  showAddModal.value = false
}
</script>

<template>
  <section class="page">
    <div class="page-inner">
      <div class="page-panel">
        <div style="display: flex; align-items: center; gap: 12px;">
          <div class="page-title" style="margin-bottom: 0;">{{ t('signed.chats') }}</div>
          <button class="secondary" type="button" :disabled="busy" @click="openAdd">{{ t('signed.add') }}</button>
        </div>

        <div v-if="err" class="status" aria-live="polite" style="margin-top: 12px;">{{ err }}</div>

        <ul class="contacts">
          <template v-if="sortedChats.length">
            <li v-for="c in sortedChats" :key="c.id">
              <button class="contact-row" type="button" :class="{ active: isActive(c.id) }" @click="onOpen(c.id)">
                <span class="name" style="display: inline-flex; align-items: center; gap: 10px;">
                  <span
                    v-if="signed.getChatOnlineState(c.id)"
                    class="status-dot"
                    :class="signed.getChatOnlineState(c.id)"
                    aria-hidden="true"
                  ></span>
                  {{ c.type === 'personal' ? (c.otherUsername ?? c.id) : (c.name ?? c.id) }}
                </span>
                <span v-if="unreadByChatId[c.id]" class="unread-badge" :aria-label="String(t('common.unreadMessages'))">
                  {{ unreadByChatId[c.id] }}
                </span>
              </button>
            </li>
          </template>
          <li v-else>
            <div class="muted">{{ t('signed.noChats') }}</div>
          </li>
        </ul>

        <div
          v-if="showAddModal"
          class="modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="signedAddTitle"
          @click="(e) => { if (e.target === e.currentTarget) closeAdd() }"
        >
          <div class="modal-card">
            <div class="modal-title" id="signedAddTitle">{{ t('signed.add') }}</div>

            <label class="field" for="friend">
              <span class="field-label">{{ t('signed.addFriend') }}</span>
              <input id="friend" v-model="friend" maxlength="64" :placeholder="String(t('signed.friendPlaceholder'))" />
            </label>
            <button class="secondary" type="button" :disabled="busy || !friend.trim()" @click="onAddFriend">
              {{ t('signed.createChat') }}
            </button>

            <label class="field" for="group-name" style="margin-top: 12px;">
              <span class="field-label">{{ t('signed.groupName') }}</span>
              <input
                id="group-name"
                v-model="groupName"
                maxlength="64"
                :placeholder="String(t('signed.groupNamePlaceholder'))"
              />
            </label>
            <button class="secondary" type="button" :disabled="busy || !groupName.trim()" @click="onCreateGroup">
              {{ t('signed.createGroup') }}
            </button>

            <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
              <button class="secondary" type="button" :disabled="busy" @click="closeAdd">{{ t('common.close') }}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
