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
const { lastUsername, username: restoredUsername } = storeToRefs(signed)

const username = ref(lastUsername.value || restoredUsername.value || '')
const password = ref('')
const expirationDays = ref(30)

const MAX_PASSWORD_LEN = 512

const mode = ref<'login' | 'register'>('login')
const isRegister = computed(() => mode.value === 'register')

const canLogin = computed(() => Boolean(username.value.trim().length >= 1 && password.value.length >= 8 && password.value.length <= MAX_PASSWORD_LEN))
const canRegister = computed(() => Boolean(username.value.trim().length >= 1 && password.value.length >= 8 && password.value.length <= MAX_PASSWORD_LEN))

const busy = ref(false)
const err = ref('')

type HelpKey = 'username' | 'password' | 'expirationDays'
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
  return ''
})

const helpBody = computed(() => {
  if (openHelp.value === 'username') return String(t('signed.help.username'))
  if (openHelp.value === 'password') return String(t('signed.help.password'))
  if (openHelp.value === 'expirationDays') return String(t('signed.help.expirationDays'))
  return ''
})

function onHelpBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) closeHelp()
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

const entropyOpen = ref(false)
const entropyHits = ref<Array<{ x: number; y: number; ms: number }>>([])
const pendingRegister = ref<{ username: string; password: string; expirationDays: number } | null>(null)
const entropyBusy = ref(false)

function resetEntropy() {
  entropyHits.value = []
  entropyBusy.value = false
  pendingRegister.value = null
}

function cancelEntropy() {
  entropyOpen.value = false
  resetEntropy()
}

async function finalizeEntropyAndRegister() {
  const p = pendingRegister.value
  if (!p) return
  entropyBusy.value = true
  try {
    // Pack 10 clicks * (x,y,ms) into bytes, then hash to 32 bytes.
    // x,y are normalized 0..65535 (field-relative), ms is 0..999.
    const buf = new Uint8Array(10 * 6)
    for (let i = 0; i < 10; i++) {
      const h = entropyHits.value[i]
      const x = Math.max(0, Math.min(65535, Math.floor((h?.x ?? 0) * 65535)))
      const y = Math.max(0, Math.min(65535, Math.floor((h?.y ?? 0) * 65535)))
      const ms = Math.max(0, Math.min(999, Math.floor(h?.ms ?? 0)))
      const o = i * 6
      buf[o + 0] = (x >>> 8) & 0xff
      buf[o + 1] = x & 0xff
      buf[o + 2] = (y >>> 8) & 0xff
      buf[o + 3] = y & 0xff
      buf[o + 4] = (ms >>> 8) & 0xff
      buf[o + 5] = ms & 0xff
    }

    const dig = await crypto.subtle.digest('SHA-256', buf as unknown as BufferSource)
    const extraEntropy = new Uint8Array(dig)

    entropyOpen.value = false
    resetEntropy()

    err.value = ''
    busy.value = true
    try {
      await signed.register({ ...p, extraEntropy })
      password.value = ''
    } catch (e: any) {
      err.value = toUserError(e)
    } finally {
      busy.value = false
    }
  } finally {
    entropyBusy.value = false
  }
}

function onEntropyClick(ev: MouseEvent) {
  if (entropyBusy.value) return
  const target = ev.currentTarget as HTMLElement | null
  if (!target) return
  const r = target.getBoundingClientRect()
  if (!r.width || !r.height) return

  const nx = (ev.clientX - r.left) / r.width
  const ny = (ev.clientY - r.top) / r.height
  const ms = Date.now() % 1000

  const next = [...entropyHits.value, { x: Math.max(0, Math.min(1, nx)), y: Math.max(0, Math.min(1, ny)), ms }]
  entropyHits.value = next
  if (next.length >= 10) {
    void finalizeEntropyAndRegister()
  }
}

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
    err.value = toUserError(e)
  } finally {
    busy.value = false
  }
}

function onRegister() {
  err.value = ''
  if (!canRegister.value) return
  if (password.value.length > MAX_PASSWORD_LEN) {
    err.value = String(t('signed.errPasswordTooLong', { max: MAX_PASSWORD_LEN }))
    return
  }

  // Collect user interaction entropy before triggering register.
  pendingRegister.value = { username: username.value.trim(), password: password.value, expirationDays: Number(expirationDays.value) }
  entropyHits.value = []
  entropyOpen.value = true
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

        <div class="setup-header-actions">
          <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
            {{ themeLabel }}
          </button>
          <button class="secondary" type="button" :aria-label="String(t('common.language'))" @click="onCycleLanguage">
            {{ t('common.language') }}: {{ t(`lang.${String(locale)}`) }}
          </button>
          <button class="secondary" type="button" @click="ui.openManageKeys">{{ t('common.manageKeys') }}</button>
          <button class="secondary" type="button" @click="ui.openAbout">{{ t('common.about') }}</button>
        </div>
      </form>
    </div>

    <div
      v-if="entropyOpen"
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="entropyTitle"
      @click="(e) => { if (e.target === e.currentTarget) cancelEntropy() }"
    >
      <div class="modal-card">
        <div class="modal-title" id="entropyTitle">{{ t('signed.entropy.title') }}</div>
        <div class="muted" style="margin-bottom: 10px;">
          {{ t('signed.entropy.instructions') }}
        </div>
        <div class="muted" style="margin-bottom: 12px;">{{ t('signed.entropy.hits', { hits: entropyHits.length, total: 10 }) }}</div>

        <div
          role="button"
          tabindex="0"
          style="width: 100%; height: 180px; border-radius: 20px; border: 1px solid var(--input-border); background: var(--glass-bg);"
          @click="onEntropyClick"
        ></div>

        <div class="modal-actions" style="margin-top: 16px;">
          <button class="secondary" type="button" :disabled="entropyBusy" @click="cancelEntropy">{{ t('common.close') }}</button>
        </div>
      </div>
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
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  line-height: 1;
  cursor: pointer;
}

.help:hover {
  color: var(--text);
  border-color: var(--text-muted);
}
</style>
