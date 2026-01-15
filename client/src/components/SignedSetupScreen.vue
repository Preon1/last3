<script setup lang="ts">
import { computed, ref, watch, watchEffect } from 'vue'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { storeToRefs } from 'pinia'
import { cycleLocale } from '../i18n'
import { useSignedStore } from '../stores/signed'

const ui = useUiStore()
const { themeLabel } = storeToRefs(ui)
const { t, locale } = useI18n()

const signed = useSignedStore()
const { lastUsername, username: restoredUsername, stayLoggedIn } = storeToRefs(signed)

const stayLoggedInModel = computed({
  get: () => Boolean(stayLoggedIn.value),
  set: (v: boolean) => signed.setStayLoggedIn(v),
})

const username = ref(lastUsername.value || restoredUsername.value || '')
const password = ref('')

function randomIntInclusive(min: number, max: number) {
  const lo = Math.min(min, max)
  const hi = Math.max(min, max)
  const range = hi - lo + 1
  try {
    const u32 = new Uint32Array(1)
    crypto.getRandomValues(u32)
    const v = u32[0] ?? 0
    return lo + (v % range)
  } catch {
    return lo + Math.floor(Math.random() * range)
  }
}

// Prefill with a random value each time the setup screen is opened.
const expirationDays = ref(randomIntInclusive(180, 365))

const MAX_PASSWORD_LEN = 512

const mode = ref<'login' | 'register'>('login')
const isRegister = computed(() => mode.value === 'register')

const canLogin = computed(() => Boolean(username.value.trim().length >= 1 && password.value.length >= 8 && password.value.length <= MAX_PASSWORD_LEN))
const canRegister = computed(() => Boolean(username.value.trim().length >= 1 && password.value.length >= 8 && password.value.length <= MAX_PASSWORD_LEN))

const busy = ref(false)
const err = ref('')

const recreateOpen = ref(false)
const recreateStep = ref<'confirm' | 'expiration'>('confirm')
const recreateBusy = ref(false)
const recreateErr = ref('')

type HelpKey = 'username' | 'password' | 'expirationDays' | 'stayLoggedIn'
const openHelp = ref<HelpKey | null>(null)

function toggleHelp(key: HelpKey) {
  openHelp.value = openHelp.value === key ? null : key
}

function closeHelp() {
  openHelp.value = null
}

watchEffect((onCleanup) => {
  if (!openHelp.value) return

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape') closeHelp()
  }

  document.addEventListener('keydown', onKeyDown)
  onCleanup(() => {
    document.removeEventListener('keydown', onKeyDown)
  })
})

const helpTitle = computed(() => {
  if (openHelp.value === 'username') return String(t('signed.username'))
  if (openHelp.value === 'password') return String(t('signed.password'))
  if (openHelp.value === 'expirationDays') return String(t('signed.expirationDays'))
  if (openHelp.value === 'stayLoggedIn') return String(t('signed.stayLoggedIn'))
  return ''
})

const helpBody = computed(() => {
  if (openHelp.value === 'username') return String(t('signed.help.username'))
  if (openHelp.value === 'password') return String(t('signed.help.password'))
  if (openHelp.value === 'expirationDays') return String(t('signed.help.expirationDays'))
  if (openHelp.value === 'stayLoggedIn') {
    return `${String(t('signed.stayLoggedInHelp'))}\n\n${String(t('signed.autoUnlockOnDevice'))}`
  }
  return ''
})

function onHelpBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) closeHelp()
}

function onRecreateBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) closeRecreate()
}

function openRecreate() {
  recreateErr.value = ''
  recreateBusy.value = false
  recreateStep.value = 'confirm'
  recreateOpen.value = true
}

function closeRecreate() {
  recreateErr.value = ''
  recreateBusy.value = false
  recreateStep.value = 'confirm'
  recreateOpen.value = false
}

function proceedRecreate() {
  recreateErr.value = ''
  // Prefill like registration.
  expirationDays.value = randomIntInclusive(180, 365)
  recreateStep.value = 'expiration'
}

async function confirmRecreate() {
  recreateErr.value = ''
  const u = username.value.trim()
  if (!u) return

  recreateBusy.value = true
  try {
    await signed.recreateAccount({ username: u, password: password.value, expirationDays: Number(expirationDays.value) })
    password.value = ''
    closeRecreate()
  } catch (e: any) {
    recreateErr.value = toUserError(e)
  } finally {
    recreateBusy.value = false
  }
}

function toUserError(e: any): string {
  const msg = typeof e?.message === 'string' ? e.message : String(e)
  if (msg === 'No local key found') return String(t('signed.errNoLocalKey'))
  if (msg === 'Invalid credentials') return String(t('signed.errInvalidCredentials'))
  if (msg === 'Unauthorized') return String(t('signed.errUnauthorized'))
  if (msg === 'Request failed') return String(t('signed.genericError'))
  return msg
}

watch(
  () => [username.value, password.value, mode.value],
  () => {
    if (err.value) err.value = ''
  },
)

// Entropy collection removed: WebCrypto RNG is sufficient.

function onCycleLanguage() {
  cycleLocale()
}

async function onLogin() {
  err.value = ''
  if (!canLogin.value) return
  if (password.value.length > MAX_PASSWORD_LEN) {
    err.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }
  busy.value = true
  try {
    await signed.login({ username: username.value.trim(), password: password.value })
    password.value = ''
  } catch (e: any) {
    const msg = typeof e?.message === 'string' ? e.message : String(e)
    if (msg === 'User not found') {
      err.value = ''
      openRecreate()
      return
    }
    err.value = toUserError(e)
  } finally {
    busy.value = false
  }
}

async function onRegister() {
  err.value = ''
  if (!canRegister.value) return
  if (password.value.length > MAX_PASSWORD_LEN) {
    err.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  const u = username.value.trim()
  if (!u) return

  // Check name availability before triggering register.
  busy.value = true
  try {
    const r = await fetch('/api/auth/check-username', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u }),
    })
    const j = await r.json().catch(() => ({} as any))
    if (!r.ok) throw new Error(typeof (j as any)?.error === 'string' ? String((j as any).error) : 'Request failed')
    if ((j as any)?.exists === true) {
      err.value = String(t('signed.errUsernameExists'))
      return
    }
  } catch (e: any) {
    err.value = toUserError(e)
    return
  } finally {
    busy.value = false
  }

  // Register directly (no entropy collection step).
  err.value = ''
  busy.value = true
  try {
    await signed.register({ username: u, password: password.value, expirationDays: Number(expirationDays.value) })
    password.value = ''
  } catch (e: any) {
    err.value = toUserError(e)
  } finally {
    busy.value = false
  }
}

function toggleMode() {
  mode.value = mode.value === 'login' ? 'register' : 'login'
}
</script>

<template>
  <section class="setup">
    <div class="setup-card">
      <div class="setup-header">
        <div class="setup-brand">
          <img class="logo logo-lg" src="/lrcom_logo.png" alt="Last" />
          <div>
            <div class="setup-title">Last</div>
            <div class="setup-subtitle muted">{{ t('signed.subtitle') }}</div>
          </div>
        </div>

        <div class="setup-toggle">
          <button class="secondary" tabindex="1" type="button" @click="toggleMode">
            {{ isRegister ? t('signed.login') : t('signed.register') }}
          </button>
        </div>
      </div>

      <form class="setup-form" autocomplete="off" @submit.prevent="isRegister ? onRegister() : onLogin()">
        <label class="field" for="signed-username">
          <div class="field-label-row">
            <span class="field-label">{{ t('signed.username') }}</span>
            <button
              class="help"
              type="button"
              :aria-label="String(t('signed.help.usernameAria'))"
              @click="toggleHelp('username')"
              tabindex="7"
            >
              ?
            </button>
          </div>
          <input
            tabindex="2"
            id="signed-username"
            v-model="username"
            maxlength="64"
            inputmode="text"
            :placeholder="String(t('signed.usernamePlaceholder'))"
          />
        </label>

        <label class="field" for="signed-password">
          <div class="field-label-row">
            <span class="field-label">{{ t('signed.password') }}</span>
            <button
              class="help"
              type="button"
              :aria-label="String(t('signed.help.passwordAria'))"
              @click="toggleHelp('password')"
              tabindex="8"
            >
              ?
            </button>
          </div>
          <input
            tabindex="3"
            id="signed-password"
            v-model="password"
            type="password"
            minlength="8"
            maxlength="512"
            :placeholder="String(t('signed.passwordPlaceholder'))"
          />
        </label>

        <label v-if="isRegister" class="field" for="signed-exp">
          <div class="field-label-row">
            <span class="field-label">{{ t('signed.expirationDays') }}</span>
            <button
              tabindex="9"
              class="help"
              type="button"
              :aria-label="String(t('signed.help.expirationDaysAria'))"
              @click="toggleHelp('expirationDays')"
            >
              ?
            </button>
          </div>
          <input tabindex="4" id="signed-exp" v-model.number="expirationDays" type="number" min="7" max="365" />
        </label>

        
        <div class="setup-actions">
          <button v-if="!isRegister" class="join" tabindex="5" type="submit" :disabled="busy || !canLogin">{{ t('signed.login') }}</button>
          <button v-else class="join" tabindex="6" type="submit" :disabled="busy || !canRegister">{{ t('signed.register') }}</button>
        </div>
        
        <div v-if="err" class="status" aria-live="polite">{{ err }}</div>
        
        <div class="stay-row">
          <div class="field-label-row">
            <input tabindex="10" type="checkbox" v-model="stayLoggedInModel" />
            <span class="field-label">{{ t('signed.stayLoggedIn') }}</span>
            <button
              class="help"
              type="button"
              :aria-label="String(t('signed.help.stayLoggedInAria'))"
              @click="toggleHelp('stayLoggedIn')"
              tabindex="11"
            >
              ?
            </button>
          </div>
        </div>

        <div class="setup-header-actions">
          <button class="secondary small-font" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
            {{ themeLabel }}
          </button>
          <button class="secondary small-font" type="button" :aria-label="String(t('common.language'))" @click="onCycleLanguage">
            {{ t('common.language') }}: {{ t(`lang.${String(locale)}`) }}
          </button>
          <button class="secondary small-font" type="button" @click="ui.openManageKeys">{{ t('common.manageKeys') }}</button>
          <button class="secondary small-font" type="button" @click="ui.openAbout">{{ t('common.about') }}</button>
        </div>
      </form>
    </div>

    <div
      v-if="openHelp"
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="helpTitle"
      @click="onHelpBackdropClick"
    >
      <div class="modal-card">
        <div class="modal-title" id="helpTitle">{{ helpTitle }}</div>
        <div class="muted" style="white-space: pre-line;">{{ helpBody }}</div>
        <div class="modal-actions" style="margin-top: 16px;">
          <button class="secondary" type="button" @click="closeHelp">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>

    <div
      v-if="recreateOpen"
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="recreateTitle"
      @click="onRecreateBackdropClick"
    >
      <div class="modal-card" @click.stop>
        <div class="modal-title" id="recreateTitle">{{ t('signed.recreate.title') }}</div>

        <div v-if="recreateStep === 'confirm'" class="muted" style="white-space: pre-line;">
          {{ t('signed.recreate.body', { username: username.trim() }) }}
        </div>

        <div v-else class="muted" style="white-space: pre-line;">
          {{ t('signed.recreate.expirationHint') }}
        </div>

        <label v-if="recreateStep === 'expiration'" class="field" for="recreate-exp">
          <div class="field-label-row">
            <span class="field-label">{{ t('signed.expirationDays') }}</span>
          </div>
          <input id="recreate-exp" v-model.number="expirationDays" type="number" min="7" max="365" />
        </label>

        <div v-if="recreateErr" class="status" aria-live="polite">{{ recreateErr }}</div>

        <div class="modal-actions" style="margin-top: 16px;">
          <button class="secondary" type="button" :disabled="recreateBusy" @click="closeRecreate">{{ t('signed.recreate.cancel') }}</button>
          <button
            v-if="recreateStep === 'confirm'"
            class="secondary"
            type="button"
            :disabled="recreateBusy"
            @click="proceedRecreate"
          >
            {{ t('signed.recreate.proceed') }}
          </button>
          <button
            v-else
            class="join"
            type="button"
            :disabled="recreateBusy"
            @click="confirmRecreate"
          >
            {{ t('signed.recreate.create') }}
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.field-label-row {
  display: flex;
  align-items: center;
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
}

.help:hover {
  color: var(--text);
  border-color: var(--text-muted);
}

.stay-row {
  display: grid;
  gap: 6px;
}

.stay-row input{
  flex-grow:0;
  margin:0;
}

.stay-help {
  font-size: 12px;
  line-height: 1.35;
}
</style>
