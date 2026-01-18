<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'
import { useToastStore } from '../stores/toast'
import { decryptLocalUsername, decryptPrivateKeyJwk, encryptLocalUsername, encryptPrivateKeyJwk } from '../utils/signedCrypto'
import { LocalEntity, localData } from '../utils/localData'

type StoredKeyV2 = {
  v: 2
  encryptedUsername: string
  encryptedPrivateKey: string
}

const DOWNLOAD_NAME = 'last_keys.json'

const MAX_PASSWORD_LEN = 512

const ui = useUiStore()
const signed = useSignedStore()
const toast = useToastStore()
const { manageKeysOpen } = storeToRefs(ui)
const { t } = useI18n()

type Page =
  | 'main'
  | 'download'
  | 'downloadSpecific'
  | 'importConfirm'
  | 'changePasswordFind'
  | 'changePasswordNew'
  | 'remove'
  | 'removeAllConfirm'
  | 'removeSpecific'
  | 'removeSpecificConfirm'

const page = ref<Page>('main')

const refreshTick = ref(0)

const dlUsername = ref('')
const dlPassword = ref('')
const dlBusy = ref(false)
const dlErr = ref('')

const rmUsername = ref('')
const rmPassword = ref('')
const rmBusy = ref(false)
const rmErr = ref('')
const rmFoundEntry = ref<StoredKeyV2 | null>(null)
const rmFoundUsername = ref<string | null>(null)

const chUsername = ref('')
const chOldPassword = ref('')
const chNewPassword = ref('')
const chNewPassword2 = ref('')
const chBusy = ref(false)
const chErr = ref('')
const chFoundEntry = ref<StoredKeyV2 | null>(null)
const chFoundUsername = ref<string | null>(null)
const chFoundPrivateJwk = ref<string | null>(null)

type ImportPlan = {
  merged: StoredKeyV2[]
  read: number
  added: number
  ignored: number
  invalid: number
}

const importPlan = ref<ImportPlan | null>(null)

function refresh() {
  refreshTick.value++
}

function loadKeyEntries(): StoredKeyV2[] {
  void refreshTick.value
  const arr = localData.getJson<any[]>(LocalEntity.SignedKeys)
  if (!Array.isArray(arr)) return []
  const out: StoredKeyV2[] = []
  for (const it of arr) {
    if (it && it.v === 2 && typeof it.encryptedUsername === 'string' && typeof it.encryptedPrivateKey === 'string') {
      out.push({ v: 2, encryptedUsername: it.encryptedUsername, encryptedPrivateKey: it.encryptedPrivateKey })
    }
  }
  return out
}

function saveKeyEntries(next: StoredKeyV2[]) {
  localData.setJson(LocalEntity.SignedKeys, next)
}

const keyEntries = computed(() => loadKeyEntries())
const totalKeyCount = computed(() => keyEntries.value.length)
const hasAnyKeys = computed(() => totalKeyCount.value > 0)

function openDownloadSpecificPage() {
  dlErr.value = ''
  dlPassword.value = ''
  page.value = 'downloadSpecific'
}

function openRemoveSpecificPage() {
  rmErr.value = ''
  rmPassword.value = ''
  rmFoundEntry.value = null
  rmFoundUsername.value = null
  page.value = 'removeSpecific'
}

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

function toastInfo(title: string, message?: string) {
  toast.push({ title, message, variant: 'info', timeoutMs: 6000 })
}

function toastErr(title: string, message?: string) {
  toast.error(title, message)
}

function resetStateOnOpen() {
  refresh()
  page.value = 'main'

  dlUsername.value = ''
  dlPassword.value = ''
  dlBusy.value = false
  dlErr.value = ''

  rmUsername.value = ''
  rmPassword.value = ''
  rmBusy.value = false
  rmErr.value = ''
  rmFoundEntry.value = null
  rmFoundUsername.value = null

  chUsername.value = ''
  chOldPassword.value = ''
  chNewPassword.value = ''
  chNewPassword2.value = ''
  chBusy.value = false
  chErr.value = ''
  chFoundEntry.value = null
  chFoundUsername.value = null
  chFoundPrivateJwk.value = null

  importPlan.value = null
}

function goBack() {
  dlErr.value = ''
  rmErr.value = ''
  chErr.value = ''

  if (page.value === 'downloadSpecific') {
    page.value = 'download'
    return
  }
  if (page.value === 'download') {
    page.value = 'main'
    return
  }
  if (page.value === 'importConfirm') {
    importPlan.value = null
    page.value = 'main'
    return
  }
  if (page.value === 'changePasswordFind') {
    page.value = 'main'
    return
  }
  if (page.value === 'changePasswordNew') {
    chNewPassword.value = ''
    chNewPassword2.value = ''
    chFoundPrivateJwk.value = null
    chFoundEntry.value = null
    chFoundUsername.value = null
    page.value = 'changePasswordFind'
    return
  }
  if (page.value === 'removeAllConfirm') {
    page.value = 'remove'
    return
  }
  if (page.value === 'removeSpecific') {
    page.value = 'remove'
    return
  }
  if (page.value === 'removeSpecificConfirm') {
    page.value = 'removeSpecific'
    return
  }
  if (page.value === 'remove') {
    page.value = 'main'
    return
  }

  ui.closeManageKeys()
}

const headerTitle = computed(() => {
  if (page.value === 'main') return String(t('signed.keys.title'))
  if (page.value === 'download') return String(t('signed.keys.download'))
  if (page.value === 'downloadSpecific') return String(t('signed.keys.downloadSpecific'))
  if (page.value === 'importConfirm') return String(t('signed.keys.addFromFile'))
  if (page.value === 'changePasswordFind') return String(t('signed.keys.changePassword'))
  if (page.value === 'changePasswordNew') return String(t('signed.keys.changePassword'))
  if (page.value === 'remove') return String(t('signed.keys.remove'))
  if (page.value === 'removeAllConfirm') return String(t('signed.keys.removeAll'))
  return String(t('signed.keys.removeSpecific'))
})

watchEffect((onCleanup) => {
  if (!manageKeysOpen.value) return

  resetStateOnOpen()

  const onKeyDown = (ev: KeyboardEvent) => {
    if (ev.key === 'Escape') {
      if (page.value !== 'main') goBack()
      else ui.closeManageKeys()
    }

    // UX sugar: Enter to confirm primary action in some flows.
    // (Avoid interfering with textarea newline behavior.)
    if (ev.key === 'Enter') {
      if (ev.shiftKey || ev.ctrlKey || ev.altKey || ev.metaKey) return
      const target = ev.target
      if (target instanceof HTMLTextAreaElement) return

      if (page.value === 'downloadSpecific') {
        if (dlBusy.value) return
        ev.preventDefault()
        void onDownloadSpecific()
        return
      }

      if (page.value === 'importConfirm') {
        ev.preventDefault()
        confirmImport()
        return
      }

      if (page.value === 'changePasswordFind') {
        if (chBusy.value) return
        ev.preventDefault()
        void findKeyForPasswordChange()
        return
      }

      if (page.value === 'changePasswordNew') {
        if (chBusy.value) return
        ev.preventDefault()
        void applyPasswordChange()
        return
      }

      if (page.value === 'removeSpecific') {
        if (rmBusy.value) return
        ev.preventDefault()
        void findKeyForRemoval()
        return
      }
    }
  }
  document.addEventListener('keydown', onKeyDown)
  onCleanup(() => document.removeEventListener('keydown', onKeyDown))
})

function onDownloadAll() {
  const list = keyEntries.value
  if (!list.length) return
  downloadJson(list)
  toastInfo(String(t('signed.keys.downloadAll')), String(t('signed.keys.downloadAllOk', { count: list.length })))
}

function openChangePasswordPage() {
  chErr.value = ''
  chOldPassword.value = ''
  chNewPassword.value = ''
  chNewPassword2.value = ''
  chFoundEntry.value = null
  chFoundUsername.value = null
  chFoundPrivateJwk.value = null
  page.value = 'changePasswordFind'
}

async function findKeyForPasswordChange() {
  chErr.value = ''
  chFoundEntry.value = null
  chFoundUsername.value = null
  chFoundPrivateJwk.value = null

  const u = chUsername.value.trim()
  const pw = chOldPassword.value
  if (!u || !pw) {
    chErr.value = String(t('signed.keys.specificMissing'))
    return
  }
  if (pw.length > MAX_PASSWORD_LEN) {
    chErr.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  chBusy.value = true
  try {
    const list = keyEntries.value
    for (const entry of list) {
      try {
        const decU = await decryptLocalUsername({ encrypted: entry.encryptedUsername, password: pw })
        if (decU !== u) continue

        const privateJwk = await decryptPrivateKeyJwk({ encrypted: entry.encryptedPrivateKey, password: pw })

        chFoundEntry.value = entry
        chFoundUsername.value = u
        chFoundPrivateJwk.value = privateJwk
        chOldPassword.value = ''
        chNewPassword.value = ''
        chNewPassword2.value = ''
        page.value = 'changePasswordNew'
        return
      } catch {
        // ignore
      }
    }
    chErr.value = String(t('signed.keys.specificNotFound'))
  } finally {
    chBusy.value = false
  }
}

async function applyPasswordChange() {
  chErr.value = ''
  const entry = chFoundEntry.value
  const u = chFoundUsername.value
  const privateJwk = chFoundPrivateJwk.value
  if (!entry || !u || !privateJwk) {
    chErr.value = String(t('signed.keys.specificNotFound'))
    return
  }

  const pw1 = chNewPassword.value
  const pw2 = chNewPassword2.value
  if (!pw1 || !pw2) {
    chErr.value = String(t('signed.keys.changePasswordNewMissing'))
    return
  }
  if (pw1 !== pw2) {
    chErr.value = String(t('signed.keys.changePasswordMismatch'))
    return
  }
  if (pw1.length < 8) {
    chErr.value = String(t('signed.passwordPlaceholder'))
    return
  }
  if (pw1.length > MAX_PASSWORD_LEN) {
    chErr.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  chBusy.value = true
  try {
    const encryptedUsername = await encryptLocalUsername({ username: u, password: pw1 })
    const encryptedPrivateKey = await encryptPrivateKeyJwk({ privateJwk, password: pw1 })
    const updated: StoredKeyV2 = { v: 2, encryptedUsername, encryptedPrivateKey }

    const existing = keyEntries.value
    const removeSig = `${entry.encryptedUsername}\n${entry.encryptedPrivateKey}`
    const next: StoredKeyV2[] = []
    const seen = new Set<string>()

    for (const k of existing) {
      const sig = `${k.encryptedUsername}\n${k.encryptedPrivateKey}`
      if (sig === removeSig) continue
      if (seen.has(sig)) continue
      seen.add(sig)
      next.push(k)
    }

    const updatedSig = `${updated.encryptedUsername}\n${updated.encryptedPrivateKey}`
    if (!seen.has(updatedSig)) next.push(updated)

    if (next.length > 0) saveKeyEntries(next)
    else localData.remove(LocalEntity.SignedKeys)

    refresh()
    toastInfo(String(t('signed.keys.changePassword')), String(t('signed.keys.changePasswordOk')))

    chOldPassword.value = ''
    chNewPassword.value = ''
    chNewPassword2.value = ''
    chFoundEntry.value = null
    chFoundUsername.value = null
    chFoundPrivateJwk.value = null
    page.value = 'main'
  } catch (e: any) {
    chErr.value = typeof e?.message === 'string' ? e.message : String(e)
    toastErr(String(t('signed.keys.changePassword')), chErr.value)
  } finally {
    chBusy.value = false
  }
}

async function onDownloadSpecific() {
  dlErr.value = ''
  const u = dlUsername.value.trim()
  const pw = dlPassword.value
  if (!u || !pw) {
    dlErr.value = String(t('signed.keys.specificMissing'))
    return
  }

  if (pw.length > MAX_PASSWORD_LEN) {
    dlErr.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  dlBusy.value = true
  try {
    const list = keyEntries.value
    for (const entry of list) {
      try {
        const dec = await decryptLocalUsername({ encrypted: entry.encryptedUsername, password: pw })
        if (dec === u) {
          downloadJson([entry])
          page.value = 'download'
          toastInfo(String(t('signed.keys.downloadSpecific')), String(t('signed.keys.downloadOneOk')))
          return
        }
      } catch {
        // ignore
      }
    }
    dlErr.value = String(t('signed.keys.specificNotFound'))
  } finally {
    dlBusy.value = false
  }
}

function removeAllLocalKeys() {
  rmErr.value = ''
  rmBusy.value = true
  try {
    localData.remove(LocalEntity.SignedKeys)

    try {
      // Force complete logout and clear session traces.
      signed.logout(true)
    } catch {
      // ignore
    }

    refresh()
    page.value = 'remove'
    toastInfo(String(t('signed.keys.removeAll')), String(t('signed.keys.removeAllOk')))
  } catch (e: any) {
    rmErr.value = typeof e?.message === 'string' ? e.message : String(e)
    toastErr(String(t('signed.keys.removeAll')), rmErr.value)
  } finally {
    rmBusy.value = false
  }
}

async function findKeyForRemoval() {
  rmErr.value = ''
  rmFoundEntry.value = null
  rmFoundUsername.value = null

  const u = rmUsername.value.trim()
  const pw = rmPassword.value
  if (!u || !pw) {
    rmErr.value = String(t('signed.keys.specificMissing'))
    return
  }
  if (pw.length > MAX_PASSWORD_LEN) {
    rmErr.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  rmBusy.value = true
  try {
    const list = keyEntries.value
    for (const entry of list) {
      try {
        const dec = await decryptLocalUsername({ encrypted: entry.encryptedUsername, password: pw })
        if (dec === u) {
          rmFoundEntry.value = entry
          rmFoundUsername.value = u
          page.value = 'removeSpecificConfirm'
          return
        }
      } catch {
        // ignore
      }
    }
    rmErr.value = String(t('signed.keys.specificNotFound'))
  } finally {
    rmBusy.value = false
  }
}

function removeSpecificKeyNow() {
  rmErr.value = ''
  const entry = rmFoundEntry.value
  const u = rmFoundUsername.value
  if (!entry || !u) {
    rmErr.value = String(t('signed.keys.specificNotFound'))
    return
  }

  rmBusy.value = true
  try {
    const existing = keyEntries.value
    const sigToRemove = `${entry.encryptedUsername}\n${entry.encryptedPrivateKey}`
    const next = existing.filter((k) => `${k.encryptedUsername}\n${k.encryptedPrivateKey}` !== sigToRemove)
    if (next.length > 0) saveKeyEntries(next)
    else localData.remove(LocalEntity.SignedKeys)

    refresh()
    page.value = 'remove'
    rmFoundEntry.value = null
    rmFoundUsername.value = null
    rmPassword.value = ''
    toastInfo(String(t('signed.keys.removeSpecific')), String(t('signed.keys.removeOneOk')))
  } catch (e: any) {
    rmErr.value = typeof e?.message === 'string' ? e.message : String(e)
    toastErr(String(t('signed.keys.removeSpecific')), rmErr.value)
  } finally {
    rmBusy.value = false
  }
}

const fileInput = ref<HTMLInputElement | null>(null)

function onPickFile() {
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

    importPlan.value = {
      merged,
      read: incoming.length,
      added,
      ignored,
      invalid: invalid.length,
    }
    page.value = 'importConfirm'
  } catch (e: any) {
    const msg = typeof e?.message === 'string' ? e.message : String(e)
    toastErr(String(t('signed.keys.addFromFile')), msg)
  }
}

function confirmImport() {
  const plan = importPlan.value
  if (!plan) {
    page.value = 'main'
    return
  }

  try {
    if (plan.merged.length > 0) saveKeyEntries(plan.merged)
    else localData.remove(LocalEntity.SignedKeys)

    refresh()

    toastInfo(
      String(t('signed.keys.addFromFile')),
      String(
        t('signed.keys.importResult', {
          read: plan.read,
          added: plan.added,
          ignored: plan.ignored,
          invalid: plan.invalid,
        }),
      ),
    )
  } catch (e: any) {
    const msg = typeof e?.message === 'string' ? e.message : String(e)
    toastErr(String(t('signed.keys.addFromFile')), msg)
  } finally {
    importPlan.value = null
    page.value = 'main'
  }
}

</script>

<template>
  <div v-if="manageKeysOpen" class="modal" role="dialog" aria-modal="true" aria-labelledby="keysTitle" @click="onBackdropClick">
    <div class="modal-card" @click.stop>
      <div class="modal-title keys-title-bar" id="keysTitle">
        <button
          v-if="page !== 'main'"
          class="secondary icon-only"
          type="button"
          :aria-label="String(t('common.back'))"
          @click="goBack"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#bracket-left"></use></svg>
        </button>
        <span>{{ headerTitle }}</span>
      </div>

      <div v-if="page === 'main'" class="muted keys-description">{{ t('signed.keys.description') }}</div>

      <div v-if="page === 'main'" class="status keys-count">
        {{ t('signed.keys.countOnDevice', { count: totalKeyCount }) }}
      </div>

      <div v-if="page === 'main'" class="modal-actions keys-actions">
        <button class="secondary" type="button" @click="onPickFile">{{ t('signed.keys.addFromFile') }}</button>
        <button class="secondary" type="button" :disabled="!hasAnyKeys" @click="page = 'download'">{{ t('signed.keys.download') }}</button>
        <button class="secondary" type="button" :disabled="!hasAnyKeys" @click="openChangePasswordPage">{{ t('signed.keys.changePassword') }}</button>
        <button class="secondary" type="button" :disabled="!hasAnyKeys" @click="page = 'remove'">{{ t('signed.keys.remove') }}</button>
        <button class="secondary" type="button" @click="ui.closeManageKeys">{{ t('common.close') }}</button>
      </div>

      <div v-else-if="page === 'download'" class="modal-actions keys-actions">
        <button class="secondary" type="button" :disabled="!hasAnyKeys" @click="onDownloadAll">{{ t('signed.keys.downloadAll') }}</button>
        <button
          class="secondary"
          type="button"
          :disabled="!hasAnyKeys"
          @click="openDownloadSpecificPage"
        >
          {{ t('signed.keys.downloadSpecific') }}
        </button>
      </div>

      <div v-else-if="page === 'downloadSpecific'">
        <div class="muted keys-subhint">{{ t('signed.keys.specificHint') }}</div>

        <label class="field" for="keys-dl-username">
          <span class="field-label">{{ t('signed.username') }}</span>
          <input id="keys-dl-username" v-model="dlUsername" maxlength="64" inputmode="text" />
        </label>

        <label class="field" for="keys-dl-password">
          <span class="field-label">{{ t('signed.password') }}</span>
          <input id="keys-dl-password" v-model="dlPassword" type="password" minlength="8" maxlength="512" />
        </label>

        <div v-if="dlErr" class="status keys-error" aria-live="polite">{{ dlErr }}</div>

        <div class="modal-actions keys-actions-single">
          <button class="secondary" type="button" :disabled="dlBusy" @click="onDownloadSpecific">{{ t('signed.keys.download') }}</button>
        </div>
      </div>

      <div v-else-if="page === 'importConfirm'">
        <div class="muted keys-subhint">{{ t('signed.keys.importConfirmHint') }}</div>

        <div class="status keys-description">
          {{
            t('signed.keys.importResult', {
              read: importPlan?.read ?? 0,
              added: importPlan?.added ?? 0,
              ignored: importPlan?.ignored ?? 0,
              invalid: importPlan?.invalid ?? 0,
            })
          }}
        </div>

        <div class="modal-actions keys-actions-single">
          <button class="secondary" type="button" @click="confirmImport">{{ t('signed.keys.importConfirmProceed') }}</button>
        </div>
      </div>

      <div v-else-if="page === 'changePasswordFind'">
        <div class="muted keys-subhint">{{ t('signed.keys.changePasswordHint') }}</div>

        <label class="field" for="keys-ch-username">
          <span class="field-label">{{ t('signed.username') }}</span>
          <input id="keys-ch-username" v-model="chUsername" maxlength="64" inputmode="text" />
        </label>

        <label class="field" for="keys-ch-old-password">
          <span class="field-label">{{ t('signed.password') }}</span>
          <input id="keys-ch-old-password" v-model="chOldPassword" type="password" minlength="8" maxlength="512" />
        </label>

        <div v-if="chErr" class="status keys-error" aria-live="polite">{{ chErr }}</div>

        <div class="modal-actions keys-actions-single">
          <button class="secondary" type="button" :disabled="chBusy" @click="findKeyForPasswordChange">{{ t('common.proceed') }}</button>
        </div>
      </div>

      <div v-else-if="page === 'changePasswordNew'">
        <div class="status keys-warning">{{ t('signed.keys.changePasswordWarning') }}</div>

        <label class="field" for="keys-ch-new-password">
          <span class="field-label">{{ t('signed.keys.newPassword') }}</span>
          <input id="keys-ch-new-password" v-model="chNewPassword" type="password" minlength="8" maxlength="512" />
        </label>

        <label class="field" for="keys-ch-new-password2">
          <span class="field-label">{{ t('signed.keys.repeatNewPassword') }}</span>
          <input id="keys-ch-new-password2" v-model="chNewPassword2" type="password" minlength="8" maxlength="512" />
        </label>

        <div v-if="chErr" class="status keys-error" aria-live="polite">{{ chErr }}</div>

        <div class="modal-actions keys-actions-single">
          <button class="secondary" type="button" :disabled="chBusy" @click="applyPasswordChange">{{ t('signed.keys.changePasswordConfirm') }}</button>
        </div>
      </div>

      <div v-else-if="page === 'remove'" class="modal-actions keys-actions">
        <button class="secondary" type="button" :disabled="!hasAnyKeys" @click="page = 'removeAllConfirm'">{{ t('signed.keys.removeAll') }}</button>
        <button
          class="secondary"
          type="button"
          :disabled="!hasAnyKeys"
          @click="openRemoveSpecificPage"
        >
          {{ t('signed.keys.removeSpecific') }}
        </button>
      </div>

      <div v-else-if="page === 'removeAllConfirm'">
        <div class="muted keys-description">{{ t('signed.keys.removeConfirm', { count: totalKeyCount }) }}</div>
        <div v-if="rmErr" class="status keys-error" aria-live="polite">{{ rmErr }}</div>
        <div class="modal-actions keys-actions-single">
          <button class="secondary danger" type="button" :disabled="rmBusy" @click="removeAllLocalKeys">{{ t('signed.keys.removeAllConfirm') }}</button>
        </div>
      </div>

      <div v-else-if="page === 'removeSpecific'">
        <div class="muted keys-subhint">{{ t('signed.keys.removeSpecificHint') }}</div>

        <label class="field" for="keys-rm-username">
          <span class="field-label">{{ t('signed.username') }}</span>
          <input id="keys-rm-username" v-model="rmUsername" maxlength="64" inputmode="text" />
        </label>

        <label class="field" for="keys-rm-password">
          <span class="field-label">{{ t('signed.password') }}</span>
          <input id="keys-rm-password" v-model="rmPassword" type="password" minlength="8" maxlength="512" />
        </label>

        <div v-if="rmErr" class="status keys-error" aria-live="polite">{{ rmErr }}</div>

        <div class="modal-actions keys-actions-single">
          <button class="secondary" type="button" :disabled="rmBusy" @click="findKeyForRemoval">{{ t('common.proceed') }}</button>
        </div>
      </div>

      <div v-else-if="page === 'removeSpecificConfirm'">
        <div class="muted keys-description">{{ t('signed.keys.removeSpecificConfirmHint', { username: rmFoundUsername ?? '' }) }}</div>
        <div v-if="rmErr" class="status keys-error" aria-live="polite">{{ rmErr }}</div>
        <div class="modal-actions keys-actions-single">
          <button class="secondary danger" type="button" :disabled="rmBusy" @click="removeSpecificKeyNow">{{ t('signed.keys.removeSpecificConfirm') }}</button>
        </div>
      </div>

      <input ref="fileInput" class="keys-file-input" type="file" accept="application/json" @change="onFileSelected" />
    </div>
  </div>
</template>

<style scoped>
.keys-title-bar {
  display: flex;
  align-items: center;
  gap: 10px;
}

.keys-description {
  white-space: pre-line;
}

.keys-subhint {
  margin-bottom: 12px;
}

.keys-count {
  margin-top: 12px;
}

.keys-actions {
  margin-top: 14px;
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.keys-actions-single {
  margin-top: 14px;
}

.keys-error {
  color: var(--danger);
}

.keys-warning {
  white-space: pre-line;
}

.keys-file-input {
  display: none;
}
</style>
