<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { cycleLocale } from '../i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'
import { useToastStore } from '../stores/toast'
import { confirmLeave } from '../utils/confirmLeave'
import { hardReloadApp } from '../utils/hardReload'

const ui = useUiStore()
const signed = useSignedStore()
const toast = useToastStore()
const { t, locale } = useI18n()

const { themeLabel } = storeToRefs(ui)
const { username, hiddenMode, introvertMode, notificationsEnabled, pushNotificationsEnabled, stayLoggedIn, vaultPlain, publicKeyJwk } = storeToRefs(signed)

const expirationDaysDraft = ref<string>('')
const expirationBusy = ref(false)
const expirationErr = ref<string>('')

const deleteAccountOpen = ref(false)
const deleteAccountBusy = ref(false)
const deleteAccountErr = ref<string>('')

const logoutOthersBusy = ref(false)
const hardReloadBusy = ref(false)

type HelpKey = 'notifications' | 'push' | 'hiddenMode' | 'introvertMode' | 'expirationDays'
const openHelp = ref<HelpKey | null>(null)

function toggleHelp(key: HelpKey) {
  openHelp.value = openHelp.value === key ? null : key
}

function closeHelp() {
  openHelp.value = null
}

const helpTitle = computed(() => {
  if (openHelp.value === 'notifications') return String(t('notifications.settingsLabel'))
  if (openHelp.value === 'push') return String(t('notifications.pushLabel'))
  if (openHelp.value === 'hiddenMode') return String(t('signed.hiddenMode'))
  if (openHelp.value === 'introvertMode') return String(t('signed.introvertMode'))
  if (openHelp.value === 'expirationDays') return String(t('signed.expirationDays'))
  return ''
})

const helpBody = computed(() => {
  if (openHelp.value === 'notifications') return String(t('notifications.settingsHint'))
  if (openHelp.value === 'push') return String(t('notifications.pushHint'))
  if (openHelp.value === 'hiddenMode') return String(t('signed.hiddenModeHelp'))
  if (openHelp.value === 'introvertMode') return String(t('signed.introvertModeHelp'))
  if (openHelp.value === 'expirationDays') {
    const parts = [String(t('signed.expirationDaysSettingsHelp')), String(t('signed.expirationDaysRangeInfo'))]
    if (!publicKeyJwk.value) parts.push(String(t('signed.expirationDaysUnlockHint')))
    return parts.join('\n\n')
  }
  return ''
})

function onHelpBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) closeHelp()
}

function onCycleLanguage() {
  cycleLocale()
}

function onAbout() {
  ui.openAbout()
}

function onManageKeys() {
  ui.openManageKeys()
}

function onLogout() {
  if (!confirmLeave('Last')) return
  signed.logout(true)
}

async function onLogoutOtherDevices() {
  if (logoutOthersBusy.value) return
  logoutOthersBusy.value = true
  try {
    await signed.logoutOtherDevices()
    toast.push({
      title: String(t('signed.settingsToast.savedTitle')),
      message: String(t('signed.settingsToast.otherDevicesLoggedOut')),
      variant: 'info',
      timeoutMs: 3000,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const body =
      msg === 'Unauthorized'
        ? String(t('signed.errUnauthorized'))
        : msg === 'Server error' || msg === 'Request failed'
          ? String(t('signed.settingsToast.serverError'))
          : msg === 'Not logged in'
            ? String(t('signed.settingsToast.notLoggedIn'))
            : String(t('signed.genericError'))
    toast.error(String(t('signed.settingsToast.failedTitle')), body)
  } finally {
    logoutOthersBusy.value = false
  }
}

async function onLogoutAndRemoveKeyOtherDevices() {
  if (logoutOthersBusy.value) return
  try {
    const ok = window.confirm(String(t('confirm.logoutAndRemoveKeyOtherDevices')))
    if (!ok) return
  } catch {
    // ignore
  }
  logoutOthersBusy.value = true
  try {
    await signed.logoutAndRemoveKeyOtherDevices()
    toast.push({
      title: String(t('signed.settingsToast.savedTitle')),
      message: String(t('signed.settingsToast.otherDevicesLoggedOutWiped')),
      variant: 'info',
      timeoutMs: 3000,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const body =
      msg === 'Unauthorized'
        ? String(t('signed.errUnauthorized'))
        : msg === 'Server error' || msg === 'Request failed'
          ? String(t('signed.settingsToast.serverError'))
          : msg === 'Not logged in'
            ? String(t('signed.settingsToast.notLoggedIn'))
            : String(t('signed.genericError'))
    toast.error(String(t('signed.settingsToast.failedTitle')), body)
  } finally {
    logoutOthersBusy.value = false
  }
}

async function onHardReloadApp() {
  if (hardReloadBusy.value) return
  hardReloadBusy.value = true

  await hardReloadApp()
}

async function onDeleteAccount() {
  deleteAccountErr.value = ''
  deleteAccountOpen.value = true
}

function closeDeleteAccount() {
  if (deleteAccountBusy.value) return
  deleteAccountOpen.value = false
  deleteAccountErr.value = ''
}

async function onConfirmDeleteAccount() {
  deleteAccountErr.value = ''
  deleteAccountBusy.value = true
  try {
    await signed.deleteAccount()
    deleteAccountOpen.value = false
  } catch {
    deleteAccountErr.value = String(t('signed.genericError'))
  } finally {
    deleteAccountBusy.value = false
  }
}

function onGlobalKeyDown(e: KeyboardEvent) {
  if (e.key !== 'Escape') return

  if (openHelp.value) {
    e.preventDefault()
    closeHelp()
    return
  }

  if (!deleteAccountOpen.value) return
  e.preventDefault()
  closeDeleteAccount()
}

onMounted(() => {
  document.addEventListener('keydown', onGlobalKeyDown)
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onGlobalKeyDown)
})

watch(
  () => vaultPlain.value?.expirationDays,
  (next) => {
    if (expirationBusy.value) return
    if (!next) return
    expirationDaysDraft.value = String(next)
  },
  { immediate: true },
)

async function onToggleHiddenMode(ev: Event) {
  const target = ev.target as HTMLInputElement | null
  if (!target) return
  const next = Boolean(target.checked)
  try {
    await signed.updateHiddenMode(next)
    toast.push({
      title: String(t('signed.settingsToast.savedTitle')),
      message: String(t(next ? 'signed.settingsToast.hiddenModeOn' : 'signed.settingsToast.hiddenModeOff')),
      variant: 'info',
      timeoutMs: 3000,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const body =
      msg === 'Unauthorized'
        ? String(t('signed.errUnauthorized'))
        : msg === 'Server error' || msg === 'Request failed'
          ? String(t('signed.settingsToast.serverError'))
          : msg === 'Not logged in'
            ? String(t('signed.settingsToast.notLoggedIn'))
            : msg === 'vault too large'
              ? String(t('signed.settingsToast.vaultTooLarge'))
              : String(t('signed.genericError'))
    toast.error(String(t('signed.settingsToast.failedTitle')), body)
  }
}

async function onToggleIntrovertMode(ev: Event) {
  const target = ev.target as HTMLInputElement | null
  if (!target) return
  const next = Boolean(target.checked)
  try {
    await signed.updateIntrovertMode(next)
    toast.push({
      title: String(t('signed.settingsToast.savedTitle')),
      message: String(t(next ? 'signed.settingsToast.introvertModeOn' : 'signed.settingsToast.introvertModeOff')),
      variant: 'info',
      timeoutMs: 3000,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const body =
      msg === 'Unauthorized'
        ? String(t('signed.errUnauthorized'))
        : msg === 'Server error' || msg === 'Request failed'
          ? String(t('signed.settingsToast.serverError'))
          : msg === 'Not logged in'
            ? String(t('signed.settingsToast.notLoggedIn'))
            : msg === 'vault too large'
              ? String(t('signed.settingsToast.vaultTooLarge'))
              : String(t('signed.genericError'))
    toast.error(String(t('signed.settingsToast.failedTitle')), body)
  }
}

async function onToggleNotifications(ev: Event) {
  const target = ev.target as HTMLInputElement | null
  if (!target) return
  const next = Boolean(target.checked)

  if (!next) {
    signed.setNotificationsEnabledLocal(false)
    return
  }

  // Must be user-initiated to satisfy browser permission rules.
  try {
    if (typeof Notification === 'undefined') {
      signed.setNotificationsEnabledLocal(false)
      return
    }

    const perm = await Notification.requestPermission()
    if (perm !== 'granted') {
      signed.setNotificationsEnabledLocal(false)
      return
    }

    signed.setNotificationsEnabledLocal(true)
  } catch {
    signed.setNotificationsEnabledLocal(false)
  }
}

async function onTogglePushNotifications(ev: Event) {
  const target = ev.target as HTMLInputElement | null
  if (!target) return
  const next = Boolean(target.checked)

  // Only allow enabling push when stay-logged-in is enabled.
  if (!stayLoggedIn.value) {
    signed.setPushNotificationsEnabledLocal(false)
    return
  }

  if (!next) {
    await signed.disablePushNotifications()
    return
  }

  // Must be user-initiated to satisfy browser permission rules.
  try {
    // Avoid prompting for permission if server push isn't configured.
    try {
      const r = await fetch('/api/push/public-key', { cache: 'no-store' })
      const j = (await r.json().catch(() => ({}))) as { enabled?: boolean; publicKey?: string | null }
      if (!r.ok || !j?.enabled || !j?.publicKey) {
        signed.setPushNotificationsEnabledLocal(false)
        toast.error(String(t('signed.settingsToast.failedTitle')), String(t('notifications.pushServerDisabled')))
        return
      }
    } catch {
      signed.setPushNotificationsEnabledLocal(false)
      toast.error(String(t('signed.settingsToast.failedTitle')), String(t('signed.settingsToast.serverError')))
      return
    }

    if (typeof Notification === 'undefined') {
      signed.setPushNotificationsEnabledLocal(false)
      return
    }

    const perm = await Notification.requestPermission()
    if (perm !== 'granted') {
      signed.setPushNotificationsEnabledLocal(false)
      return
    }

    signed.setPushNotificationsEnabledLocal(true)
    const ok = await signed.trySyncPushSubscription()
    if (!ok) {
      signed.setPushNotificationsEnabledLocal(false)
      toast.error(String(t('toast.notificationsFailedTitle')), String(t('toast.notificationsFailedBody')))
    }
  } catch {
    signed.setPushNotificationsEnabledLocal(false)
  }
}

async function onSaveExpirationDays() {
  expirationErr.value = ''
  expirationBusy.value = true
  try {
    const n = Number(expirationDaysDraft.value)
    if (!Number.isFinite(n) || n < 7 || n > 365) {
      expirationErr.value = String(t('signed.expirationDaysRangeError'))
      toast.error(String(t('signed.settingsToast.failedTitle')), String(t('signed.expirationDaysRangeError')))
      return
    }
    await signed.updateExpirationDays(n)

    toast.push({
      title: String(t('signed.settingsToast.savedTitle')),
      message: String(t('signed.settingsToast.expirationDaysSaved', { days: n })),
      variant: 'info',
      timeoutMs: 3000,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)

    if (msg === 'Expiration days must be between 7 and 365') {
      expirationErr.value = String(t('signed.expirationDaysRangeError'))
      toast.error(String(t('signed.settingsToast.failedTitle')), String(t('signed.expirationDaysRangeError')))
      return
    }

    const body =
      msg === 'Unauthorized'
        ? String(t('signed.errUnauthorized'))
        : msg === 'Server error' || msg === 'Request failed'
          ? String(t('signed.settingsToast.serverError'))
          : msg === 'Not logged in'
            ? String(t('signed.settingsToast.notLoggedIn'))
            : msg === 'Missing public key'
              ? String(t('signed.expirationDaysUnlockHint'))
              : msg === 'vault too large'
                ? String(t('signed.settingsToast.vaultTooLarge'))
                : String(t('signed.genericError'))
    expirationErr.value = body
    toast.error(String(t('signed.settingsToast.failedTitle')), body)
  } finally {
    expirationBusy.value = false
  }
}

function notificationStateLabel() {
  try {
    if (typeof Notification === 'undefined') return String(t('notifications.state.default'))
    const p = Notification.permission
    if (p === 'granted') return String(t('notifications.state.granted'))
    if (p === 'denied') return String(t('notifications.state.denied'))
    return String(t('notifications.state.default'))
  } catch {
    return String(t('notifications.state.default'))
  }
}
</script>

<template>
  <section class="page">
    <div class="page-inner">
      <div class="headergap"></div>

      <div class="settings-tech">
        <div v-if="username">{{ t('signed.youSignedInAs') }} <strong>{{ username }}</strong></div>
      </div>

      <div class="settings-actions">
        <label class="secondary">
          <input
            type="checkbox"
            :checked="Boolean(notificationsEnabled)"
            @change="onToggleNotifications"
            :aria-label="String(t('notifications.settingsLabel'))"
          />
          <span>
            <div class="field-label-row">
              <div style="font-weight: 600;">{{ t('notifications.settingsLabel') }} {{ notificationStateLabel() }}</div>
              <button class="help" type="button" :aria-label="String(t('notifications.settingsLabel'))" @click.stop.prevent="toggleHelp('notifications')">
                ?
              </button>
            </div>
          </span>
        </label>

        <label v-if="stayLoggedIn" class="secondary">
          <input
            type="checkbox"
            :checked="Boolean(pushNotificationsEnabled)"
            @change="onTogglePushNotifications"
            :aria-label="String(t('notifications.pushLabel'))"
          />
          <span>
            <div class="field-label-row">
              <div style="font-weight: 600;">{{ t('notifications.pushLabel') }}</div>
              <button class="help" type="button" :aria-label="String(t('notifications.pushLabel'))" @click.stop.prevent="toggleHelp('push')">
                ?
              </button>
            </div>
          </span>
        </label>

        <label class="secondary">
          <input
            type="checkbox"
            :checked="Boolean(hiddenMode)"
            @change="onToggleHiddenMode"
            :aria-label="String(t('signed.hiddenMode'))"
          />
          <span>
            <div class="field-label-row">
              <div style="font-weight: 600;">{{ t('signed.hiddenMode') }}</div>
              <button class="help" type="button" :aria-label="String(t('signed.hiddenMode'))" @click.stop.prevent="toggleHelp('hiddenMode')">
                ?
              </button>
            </div>
          </span>
        </label>

        <label class="secondary">
          <input
            type="checkbox"
            :checked="Boolean(introvertMode)"
            @change="onToggleIntrovertMode"
            :aria-label="String(t('signed.introvertMode'))"
          />
          <span>
            <div class="field-label-row">
              <div style="font-weight: 600;">{{ t('signed.introvertMode') }}</div>
              <button class="help" type="button" :aria-label="String(t('signed.introvertMode'))" @click.stop.prevent="toggleHelp('introvertMode')">
                ?
              </button>
            </div>
          </span>
        </label>

        <button
          class="secondary icon-only"
          type="button"
          :aria-label="String(t('common.logout'))"
          :title="String(t('common.logout'))"
          @click="onLogout"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#logout"></use></svg>
        </button>

        <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
          {{ themeLabel }}
        </button>

        <button class="secondary" type="button" :aria-label="String(t('common.language'))" @click="onCycleLanguage">
          {{ t('common.language') }}: {{ t(`lang.${String(locale)}`) }}
        </button>

        <button class="secondary" type="button" @click="onManageKeys">{{ t('common.manageKeys') }}</button>

        <button class="secondary" type="button" @click="onAbout">{{ t('common.about') }}</button>

        <div class="card" style="margin-bottom: 0;">
          <div class="field-label-row">
            <div style="font-weight: 600;">{{ t('signed.expirationDays') }}</div>
            <button
              class="help"
              type="button"
              :aria-label="String(t('signed.expirationDays'))"
              @click.stop.prevent="toggleHelp('expirationDays')"
            >
              ?
            </button>
          </div>

          <div class="row" style="margin-top: 10px;">
            <input
              v-model="expirationDaysDraft"
              type="number"
              inputmode="numeric"
              min="7"
              max="365"
              :disabled="expirationBusy || !publicKeyJwk"
              style="max-width: 140px;"
              :aria-label="String(t('signed.expirationDays'))"
              @keydown.enter.prevent="onSaveExpirationDays"
            />
            <button class="secondary" type="button" :disabled="expirationBusy || !publicKeyJwk" @click="onSaveExpirationDays">
              {{ t('common.save') }}
            </button>
          </div>

          <div v-if="expirationErr" class="status" aria-live="polite" style="margin-top: 8px;">{{ expirationErr }}</div>
        </div>

        <button class="secondary" type="button" :disabled="logoutOthersBusy" @click="onLogoutOtherDevices">
          {{ t('signed.logoutOtherDevices') }}
        </button>

        <button class="secondary" type="button" :disabled="logoutOthersBusy" @click="onLogoutAndRemoveKeyOtherDevices">
          {{ t('signed.logoutAndRemoveKeyOtherDevices') }}
        </button>

        <button class="secondary" type="button" :disabled="hardReloadBusy" @click="onHardReloadApp">
          {{ t('signed.reloadAppNoCache') }}
        </button>

        <button class="secondary danger" type="button" @click="onDeleteAccount">{{ t('signed.deleteAccount') }}</button>

      </div>

      <div
        v-if="deleteAccountOpen"
        class="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="deleteAccountTitleSigned"
        @click="(e) => { if (e.target === e.currentTarget) closeDeleteAccount() }"
      >
        <div class="modal-card">
          <div class="modal-title" id="deleteAccountTitleSigned">{{ t('signed.deleteAccount') }}</div>

          <div class="muted" style="margin-top: 8px;">{{ t('signed.deleteAccountWarning') }}</div>
          <div v-if="deleteAccountErr" class="status" aria-live="polite" style="margin-top: 8px;">{{ deleteAccountErr }}</div>

          <div class="modal-actions">
            <button type="button" :disabled="deleteAccountBusy" @click="closeDeleteAccount">{{ t('common.cancel') }}</button>
            <button class="danger" type="button" :disabled="deleteAccountBusy" @click="onConfirmDeleteAccount">
              {{ t('signed.deleteAccount') }}
            </button>
          </div>
        </div>
      </div>

      <div v-if="openHelp" class="modal" role="dialog" aria-modal="true" aria-labelledby="helpTitleSettings" @click="onHelpBackdropClick">
        <div class="modal-card">
          <div class="modal-title" id="helpTitleSettings">{{ helpTitle }}</div>
          <div class="muted" style="white-space: pre-line;">{{ helpBody }}</div>
          <div class="modal-actions" style="margin-top: 16px;">
            <button class="secondary" type="button" @click="closeHelp">{{ t('common.close') }}</button>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.field-label-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.help {
  width: 20px;
  height: 20px;
  border-radius: 999px;
  border: 1px solid var(--input-border);
  background: transparent;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  cursor: pointer;
  font-size: 10px;
  padding: 0;
  color: var(--muted);
  margin-bottom: -1px;
  flex: 0 0 auto;
}

.help:hover {
  color: var(--text);
  border-color: var(--text-muted);
}
</style>
