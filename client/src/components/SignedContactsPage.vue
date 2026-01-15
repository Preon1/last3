<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useSignedStore } from '../stores/signed'
import { useI18n } from 'vue-i18n'
import { useToastStore } from '../stores/toast'
import { useUiStore } from '../stores/ui'

const signed = useSignedStore()
const ui = useUiStore()
const toast = useToastStore()
const { t } = useI18n()

const { chats, unreadByChatId, activeChatId } = storeToRefs(signed)

const friend = ref('')
const groupName = ref('')
const addMenuOpen = ref(false)
const addMenuRoot = ref<HTMLElement | null>(null)
const addMenuButton = ref<HTMLButtonElement | null>(null)

const addContactOpen = ref(false)
const createChatOpen = ref(false)
const busy = ref(false)
const err = ref<string>('')

type ChatFilterMode = 'all' | 'personal' | 'group'
const filterMode = ref<ChatFilterMode>('all')

const filteredChats = computed(() => {
  const list = chats.value.slice()
  if (filterMode.value === 'personal') return list.filter((c) => c.type === 'personal')
  if (filterMode.value === 'group') return list.filter((c) => c.type === 'group')
  return list
})

const sortedChats = computed(() => {
  const list = filteredChats.value.slice()
  list.sort((a, b) => {
    const ua = unreadByChatId.value[a.id] ?? 0
    const ub = unreadByChatId.value[b.id] ?? 0
    const aUnread = ua > 0
    const bUnread = ub > 0
    if (aUnread !== bUnread) return aUnread ? -1 : 1

    const ta = signed.getChatLastMessageTsMs(a.id)
    const tb = signed.getChatLastMessageTsMs(b.id)
    if (ta !== tb) return tb - ta

    // Stable-ish fallback.
    return String(b.id).localeCompare(String(a.id))
  })
  return list
})

const MONTHS_EN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function pad2(n: number) {
  return String(Math.floor(n)).padStart(2, '0')
}

function formatTimeOrDate(tsMs: number): string {
  if (!tsMs || !Number.isFinite(tsMs)) return ''
  const d = new Date(tsMs)
  const now = new Date()

  const sameDay =
    d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate()

  if (sameDay) return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`

  const day = pad2(d.getDate())
  const mon = MONTHS_EN[d.getMonth()] ?? ''
  return mon ? `${day} ${mon}` : day
}

function shorten(s: string, max: number): string {
  const v = String(s ?? '')
  if (v.length <= max) return v
  return v.slice(0, max) + '..'
}

function openShareLink() {
  addMenuOpen.value = false
  ui.openShareLink()
}

function openScanQr() {
  addMenuOpen.value = false
  ui.openScanQr()
}

function chatPreview(c: { id: string; type: 'personal' | 'group' }): string {
  const p = signed.getChatLastMessagePreview(c.id)
  if (!p) return ''

  const timeOrDate = formatTimeOrDate(p.tsMs)
  const body = shorten(String(p.text ?? '').replace(/\s+/g, ' ').trim(), 100)
  if (!body) return ''

  const parts: string[] = []
  if (timeOrDate) parts.push(timeOrDate)

  if (c.type === 'group') {
    const sender = shorten(String(p.senderUsername ?? '').trim(), 10)
    if (sender) parts.push(sender)
  }

  parts.push(body)
  return parts.join(' • ')
}

const filterLabel = computed(() => {
  const type =
    filterMode.value === 'personal'
      ? String(t('signed.filterPrivate'))
      : filterMode.value === 'group'
        ? String(t('signed.filterGroups'))
        : String(t('signed.filterAll'))
  return String(t('signed.filterShow', { type }))
})

function cycleFilterMode() {
  filterMode.value = filterMode.value === 'all' ? 'personal' : filterMode.value === 'personal' ? 'group' : 'all'
}

function isActive(id: string) {
  return (activeChatId.value ?? null) === id
}

function toggleAddMenu() {
  addMenuOpen.value = !addMenuOpen.value
}

function closeAddMenu() {
  addMenuOpen.value = false
}

function openAddContact() {
  err.value = ''
  closeAddMenu()
  addContactOpen.value = true
}

function closeAddContact() {
  addContactOpen.value = false
}

function openCreateChat() {
  err.value = ''
  closeAddMenu()
  createChatOpen.value = true
}

function closeCreateChat() {
  createChatOpen.value = false
}

function onGlobalPointerDown(e: PointerEvent) {
  if (!addMenuOpen.value) return
  const root = addMenuRoot.value
  if (!root) return
  if (!(e.target instanceof Node)) return
  if (root.contains(e.target)) return
  closeAddMenu()
}

function onGlobalKeyDown(e: KeyboardEvent) {
  if (e.key !== 'Escape') return
  if (addContactOpen.value) {
    e.preventDefault()
    closeAddContact()
    return
  }
  if (createChatOpen.value) {
    e.preventDefault()
    closeCreateChat()
    return
  }
  if (addMenuOpen.value) {
    e.preventDefault()
    closeAddMenu()
    addMenuButton.value?.focus()
  }
}

onMounted(() => {
  document.addEventListener('pointerdown', onGlobalPointerDown)
  document.addEventListener('keydown', onGlobalKeyDown)

  // Extra safety: refresh chats whenever the list page is opened.
  // WS notifications are best-effort; the list should self-heal.
  void signed.refreshChats()
})

onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onGlobalPointerDown)
  document.removeEventListener('keydown', onGlobalKeyDown)
})

async function onAddFriend() {
  err.value = ''
  const u = friend.value.trim()
  if (!u) return
  busy.value = true
  try {
    await signed.createPersonalChat(u)
    friend.value = ''
    closeAddContact()
  } catch (e: any) {
    const msg = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
    if (msg === 'self') {
      err.value = String(t('signed.cannotChatWithSelf'))
      return
    }
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
    closeCreateChat()
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

</script>

<template>
  <section class="page">
    <div class="page-inner" style="padding-bottom:0;padding-top:0;">
      <div class="page-top">
        <div class="page-panel">
          <div class="page-title">{{ t('signed.chats') }}</div>

          <div class="page-actions">

            <button class="secondary" type="button" :disabled="busy" @click="cycleFilterMode">{{ filterLabel }}</button>

            <div class="page-other-actions" ref="addMenuRoot">
              <button
                ref="addMenuButton"
                class="secondary icon-only small"
                type="button"
                aria-haspopup="menu"
                :aria-expanded="addMenuOpen ? 'true' : 'false'"
                :disabled="busy"
                :aria-label="String(t('signed.add'))"
                @click="toggleAddMenu"
              >
                <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#plus"></use></svg>
              </button>
  
              <div v-if="addMenuOpen" class="page-other-menu" role="menu">
                <button class="secondary page-other-item" type="button" role="menuitem" @click="openAddContact">
                  {{ t('signed.addContact') }}
                </button>
                <button class="secondary page-other-item" type="button" role="menuitem" @click="openCreateChat">
                  {{ t('signed.createChat') }}
                </button>
                <button class="secondary page-other-item" type="button" role="menuitem" @click="openShareLink">
                  {{ t('common.shareLink') }}
                </button>
                <button class="secondary page-other-item" type="button" role="menuitem" @click="openScanQr">
                  {{ t('common.scanQr') }}
                </button>
              </div>
            </div>
          </div>
          
        </div>

        <div v-if="err" class="status" aria-live="polite" style="margin-top: 12px;">{{ err }}</div>

      </div>

      <ul class="contacts">
        <template v-if="sortedChats.length">
          <li v-for="c in sortedChats" :key="c.id">
            <button class="contact-row" type="button" :class="{ active: isActive(c.id) }" @click="onOpen(c.id)">
              <span class="contact-row-left">
                <span class="name" style="display: inline-flex; align-items: center; gap: 10px;">
                  <span
                    v-if="c.type === 'personal' && signed.getChatOnlineState(c.id)"
                    class="status-dot"
                    :class="signed.getChatOnlineState(c.id)"
                    aria-hidden="true"
                  ></span>
                  {{ c.type === 'personal' ? (c.otherUsername ?? c.id) : (c.name ?? c.id) }}
                </span>
                <span v-if="chatPreview(c)" class="muted contact-preview">{{ chatPreview(c) }}</span>
              </span>
              <span class="contact-row-right">
                <span v-if="unreadByChatId[c.id]" class="unread-badge" :aria-label="String(t('common.unreadMessages'))">
                  {{ unreadByChatId[c.id] }}
                </span>
              </span>
            </button>
          </li>
        </template>
        <li v-else>
          <div class="muted">{{ t('signed.noChats') }}</div>
        </li>
      </ul>


      <div
        v-if="addContactOpen"
        class="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="signedAddContactTitle"
        @click="(e) => { if (e.target === e.currentTarget) closeAddContact() }"
      >
        <div class="modal-card">
          <div class="modal-title" id="signedAddContactTitle">{{ t('signed.addContact') }}</div>

          <label class="field" for="friend">
            <span class="field-label">{{ t('signed.addFriend') }}</span>
            <input id="friend" v-model="friend" maxlength="64" :placeholder="String(t('signed.friendPlaceholder'))" />
          </label>

          <div style="display: flex; justify-content: space-between; gap: 8px; margin-top: 16px;">
            <button class="secondary" type="button" :disabled="busy" @click="closeAddContact">{{ t('common.close') }}</button>
            <button class="secondary" type="button" :disabled="busy || !friend.trim()" @click="onAddFriend">
              {{ t('signed.createChat') }}
            </button>
          </div>
        </div>
      </div>

      <div
        v-if="createChatOpen"
        class="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="signedCreateChatTitle"
        @click="(e) => { if (e.target === e.currentTarget) closeCreateChat() }"
      >
        <div class="modal-card">
          <div class="modal-title" id="signedCreateChatTitle">{{ t('signed.createChat') }}</div>

          <label class="field" for="group-name">
            <span class="field-label">{{ t('signed.groupName') }}</span>
            <input
              id="group-name"
              v-model="groupName"
              maxlength="64"
              :placeholder="String(t('signed.groupNamePlaceholder'))"
            />
          </label>

          <div style="display: flex; justify-content: space-between; gap: 8px; margin-top: 16px;">
            <button class="secondary" type="button" :disabled="busy" @click="closeCreateChat">{{ t('common.close') }}</button>
            <button class="secondary" type="button" :disabled="busy || !groupName.trim()" @click="onCreateGroup">
              {{ t('signed.createGroup') }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
