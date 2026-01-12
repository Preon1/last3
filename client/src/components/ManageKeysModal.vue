<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'
import { decryptStringWithPassword } from '../utils/signedCrypto'

type StoredKeyV2 = {
  v: 2
  encryptedUsername: string
  encryptedPrivateKey: string
}

const LS_KEYS = 'lrcom-signed-keys'
const LS_LEGACY_KEY = 'lrcom-signed-key'
const DOWNLOAD_NAME = 'last_keys.json'

const MAX_PASSWORD_LEN = 512

const ui = useUiStore()
const signed = useSignedStore()
const { manageKeysOpen } = storeToRefs(ui)
const { t } = useI18n()

const refreshTick = ref(0)
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')

const specificOpen = ref(false)
const specificUsername = ref('')
const specificPassword = ref('')
const specificBusy = ref(false)
const specificErr = ref('')
const specificUsernameLocked = ref(false)

const removeOpen = ref(false)
const removeBusy = ref(false)
const removeDone = ref(false)
const removeErr = ref('')

function clearStatus() {
  status.value = ''
  statusKind.value = ''
}

function refresh() {
  refreshTick.value++
}

function loadKeyEntries(): StoredKeyV2[] {
  void refreshTick.value
  try {
    const raw = localStorage.getItem(LS_KEYS)
    if (!raw) return []
    const arr = JSON.parse(raw)
    if (!Array.isArray(arr)) return []
    const out: StoredKeyV2[] = []
    for (const it of arr) {
      if (it && it.v === 2 && typeof it.encryptedUsername === 'string' && typeof it.encryptedPrivateKey === 'string') {
        out.push({ v: 2, encryptedUsername: it.encryptedUsername, encryptedPrivateKey: it.encryptedPrivateKey })
      }
    }
    return out
  } catch {
    return []
  }
}

function hasLegacyKey(): boolean {
  void refreshTick.value
  try {
    return Boolean(localStorage.getItem(LS_LEGACY_KEY))
  } catch {
    return false
  }
}

function saveKeyEntries(next: StoredKeyV2[]) {
  localStorage.setItem(LS_KEYS, JSON.stringify(next))
}

const keyEntries = computed(() => loadKeyEntries())
const v2KeyCount = computed(() => keyEntries.value.length)
const legacyCount = computed(() => (hasLegacyKey() ? 1 : 0))
const totalKeyCount = computed(() => v2KeyCount.value + legacyCount.value)
const hasAnyKeys = computed(() => totalKeyCount.value > 0)

const loggedInUsername = computed(() => {
  const u = (signed.username ?? '').trim()
  return u || null
})

function downloadJson(obj: unknown) {
  const content = JSON.stringify(obj, null, 2)
  const blob = new Blob([content], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = DOWNLOAD_NAME
    a.style.display = 'none'
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    URL.revokeObjectURL(url)
  }
}

function onBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) ui.closeManageKeys()
}

watchEffect((onCleanup) => {
  if (!manageKeysOpen.value) return

  refresh()
  clearStatus()
  specificOpen.value = false
  removeOpen.value = false
  removeDone.value = false

  const onKeyDown = (ev: KeyboardEvent) => {
    if (ev.key === 'Escape') {
      if (specificOpen.value) specificOpen.value = false
      else if (removeOpen.value) removeOpen.value = false
      else ui.closeManageKeys()
    }
  }
  document.addEventListener('keydown', onKeyDown)
  onCleanup(() => document.removeEventListener('keydown', onKeyDown))
})

function onDownloadAll() {
  clearStatus()
  const list = keyEntries.value
  if (!list.length) return
  downloadJson(list)
  statusKind.value = 'ok'
  status.value = String(t('signed.keys.downloadAllOk', { count: list.length }))
}

function openDownloadSpecific(prefillUsername?: string, lockUsername?: boolean) {
  clearStatus()
  specificErr.value = ''
  specificPassword.value = ''
  specificUsername.value = (prefillUsername ?? '').trim()
  specificUsernameLocked.value = Boolean(lockUsername)
  specificOpen.value = true
}

async function onDownloadSpecific() {
  specificErr.value = ''
  const u = specificUsername.value.trim()
  const pw = specificPassword.value
  if (!u || !pw) {
    specificErr.value = String(t('signed.keys.specificMissing'))
    return
  }

  if (pw.length > MAX_PASSWORD_LEN) {
    specificErr.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  specificBusy.value = true
  try {
    const list = keyEntries.value
    for (const entry of list) {
      try {
        const dec = await decryptStringWithPassword({ encrypted: entry.encryptedUsername, password: pw })
        if (dec === u) {
          downloadJson([entry])
          specificOpen.value = false
          statusKind.value = 'ok'
          status.value = String(t('signed.keys.downloadOneOk'))
          return
        }
      } catch {
        // ignore
      }
    }
    specificErr.value = String(t('signed.keys.specificNotFound'))
  } finally {
    specificBusy.value = false
  }
}

function openRemoveAllConfirm() {
  clearStatus()
  removeErr.value = ''
  removeBusy.value = false
  removeDone.value = false
  removeOpen.value = true
}

function removeAllLocalKeys() {
  removeErr.value = ''
  removeBusy.value = true
  try {
    try {
      localStorage.removeItem(LS_KEYS)
      localStorage.removeItem(LS_LEGACY_KEY)
    } catch {
      // ignore
    }

    try {
      // Force complete logout and clear session traces.
      signed.logout(true)
    } catch {
      // ignore
    }

    refresh()
    removeDone.value = true
    statusKind.value = 'ok'
    status.value = String(t('signed.keys.removeAllOk'))
  } catch (e: any) {
    removeErr.value = typeof e?.message === 'string' ? e.message : String(e)
  } finally {
    removeBusy.value = false
  }
}

const fileInput = ref<HTMLInputElement | null>(null)

function onPickFile() {
  clearStatus()
  fileInput.value?.click()
}

async function onFileSelected(ev: Event) {
  const input = ev.target as HTMLInputElement | null
  const file = input?.files?.[0] ?? null
  if (!file) return

  // Reset value so selecting the same file again triggers change.
  try {
    if (input) input.value = ''
  } catch {
    // ignore
  }

  clearStatus()
  try {
    const text = await file.text()
    const parsed = JSON.parse(text)

    const incoming: StoredKeyV2[] = []
    const invalid: string[] = []

    const consider = (it: any) => {
      if (it && it.v === 2 && typeof it.encryptedUsername === 'string' && typeof it.encryptedPrivateKey === 'string') {
        incoming.push({ v: 2, encryptedUsername: it.encryptedUsername, encryptedPrivateKey: it.encryptedPrivateKey })
      } else {
        invalid.push('invalid_entry')
      }
    }

    if (Array.isArray(parsed)) {
      for (const it of parsed) consider(it)
    } else if (parsed && typeof parsed === 'object') {
      consider(parsed)
    } else {
      throw new Error(String(t('signed.keys.importBadFormat')))
    }

    const existing = keyEntries.value
    const seen = new Set(existing.map((k) => `${k.encryptedUsername}\n${k.encryptedPrivateKey}`))

    let added = 0
    let ignored = 0
    const merged = [...existing]
    for (const k of incoming) {
      const sig = `${k.encryptedUsername}\n${k.encryptedPrivateKey}`
      if (seen.has(sig)) {
        ignored++
        continue
      }
      seen.add(sig)
      merged.push(k)
      added++
    }

    if (added > 0) saveKeyEntries(merged)
    refresh()

    statusKind.value = 'ok'
    status.value = String(
      t('signed.keys.importResult', {
        read: incoming.length,
        added,
        ignored,
        invalid: invalid.length,
      }),
    )
  } catch (e: any) {
    statusKind.value = 'error'
    status.value = typeof e?.message === 'string' ? e.message : String(e)
  }
}
</script>

<template>
  <div v-if="manageKeysOpen" class="modal" role="dialog" aria-modal="true" aria-labelledby="keysTitle" @click="onBackdropClick">
    <div class="modal-card" @click.stop>
      <div class="modal-title" id="keysTitle">{{ t('signed.keys.title') }}</div>
      <div class="muted" style="white-space: pre-line;">{{ t('signed.keys.description') }}</div>

      <div class="status" style="margin-top: 12px;">
        {{ t('signed.keys.countOnDevice', { count: totalKeyCount }) }}
      </div>

      <div v-if="status" class="status" :style="{ color: statusKind === 'error' ? 'var(--danger)' : undefined }" aria-live="polite">
        {{ status }}
      </div>

      <div class="modal-actions" style="margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap;">
        <button v-if="loggedInUsername" class="secondary" type="button" @click="openDownloadSpecific(loggedInUsername ?? '', true)">
          {{ t('signed.keys.downloadUser', { username: loggedInUsername }) }}
        </button>

        <button v-if="v2KeyCount > 0" class="secondary" type="button" @click="onDownloadAll">
          {{ t('signed.keys.downloadAll') }}
        </button>

        <button v-if="v2KeyCount > 0" class="secondary" type="button" @click="openDownloadSpecific('', false)">
          {{ t('signed.keys.downloadSpecific') }}
        </button>

        <button class="secondary" type="button" @click="onPickFile">
          {{ t('signed.keys.addFromFile') }}
        </button>

        <button v-if="hasAnyKeys" class="secondary" type="button" @click="openRemoveAllConfirm">
          {{ t('signed.keys.removeAll') }}
        </button>

        <button class="secondary" type="button" @click="ui.closeManageKeys">{{ t('common.close') }}</button>
      </div>

      <input ref="fileInput" type="file" accept="application/json" style="display:none;" @change="onFileSelected" />
    </div>
  </div>

  <div
    v-if="manageKeysOpen && specificOpen"
    class="modal"
    role="dialog"
    aria-modal="true"
    aria-labelledby="keysSpecificTitle"
    @click="() => { specificOpen = false }"
  >
    <div class="modal-card" @click.stop>
      <div class="modal-title" id="keysSpecificTitle">{{ t('signed.keys.downloadSpecific') }}</div>
      <div class="muted" style="margin-bottom: 12px;">{{ t('signed.keys.specificHint') }}</div>

      <label class="field" for="keys-username">
        <span class="field-label">{{ t('signed.username') }}</span>
        <input id="keys-username" v-model="specificUsername" :disabled="specificUsernameLocked" maxlength="64" inputmode="text" />
      </label>

      <label class="field" for="keys-password">
        <span class="field-label">{{ t('signed.password') }}</span>
        <input id="keys-password" v-model="specificPassword" type="password" minlength="8" maxlength="512" />
      </label>

      <div v-if="specificErr" class="status" aria-live="polite" style="color: var(--danger);">{{ specificErr }}</div>

      <div class="modal-actions" style="margin-top: 14px;">
        <button class="secondary" type="button" :disabled="specificBusy" @click="specificOpen = false">{{ t('common.cancel') }}</button>
        <button class="secondary" type="button" :disabled="specificBusy" @click="onDownloadSpecific">{{ t('signed.keys.download') }}</button>
      </div>
    </div>
  </div>

  <div
    v-if="manageKeysOpen && removeOpen"
    class="modal"
    role="dialog"
    aria-modal="true"
    aria-labelledby="keysRemoveTitle"
    @click="() => { if (!removeBusy) removeOpen = false }"
  >
    <div class="modal-card" @click.stop>
      <div class="modal-title" id="keysRemoveTitle">{{ t('signed.keys.removeAll') }}</div>

      <div v-if="!removeDone" class="muted" style="white-space: pre-line;">
        {{ t('signed.keys.removeConfirm', { count: totalKeyCount }) }}
      </div>

      <div v-else class="status">{{ t('signed.keys.removeAllOk') }}</div>

      <div v-if="removeErr" class="status" aria-live="polite" style="color: var(--danger);">{{ removeErr }}</div>

      <div class="modal-actions" style="margin-top: 14px;">
        <button v-if="!removeDone" class="secondary" type="button" :disabled="removeBusy" @click="removeOpen = false">
          {{ t('common.cancel') }}
        </button>
        <button
          v-if="!removeDone"
          class="secondary"
          type="button"
          :disabled="removeBusy"
          style="background: rgba(255,0,0,0.10); border-color: rgba(255,0,0,0.45); color: var(--danger);"
          @click="removeAllLocalKeys"
        >
          {{ t('signed.keys.removeAllConfirm') }}
        </button>
        <button v-else class="secondary" type="button" @click="removeOpen = false">{{ t('common.close') }}</button>
      </div>
    </div>
  </div>
</template>
