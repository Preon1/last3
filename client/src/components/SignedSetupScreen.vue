<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { storeToRefs } from 'pinia'
import { cycleLocale } from '../i18n'
import { useSignedStore } from '../stores/signed'

const emit = defineEmits<{
  (e: 'login', v: { username: string; password: string }): void
  (e: 'register', v: { username: string; password: string; expirationDays: number; extraEntropy?: Uint8Array }): void
  (e: 'switchAnonymous'): void
}>()

const ui = useUiStore()
const { themeLabel } = storeToRefs(ui)
const { t, locale } = useI18n()

const signed = useSignedStore()
const { lastUsername } = storeToRefs(signed)

const username = ref(lastUsername.value || '')
const password = ref('')
const expirationDays = ref(30)

const mode = ref<'login' | 'register'>('login')
const isRegister = computed(() => mode.value === 'register')

const subtitle = computed(() => {
  // Keep i18n keys minimal by composing existing translations.
  return isRegister.value ? `${t('signed.subtitle')} ${t('signed.register')}.` : `${t('signed.subtitle')} ${t('signed.login')}.`
})

const canSubmit = computed(() => Boolean(username.value.trim() && password.value))

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
    emit('register', { ...p, extraEntropy })
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

function onLogin() {
  if (!canSubmit.value) return
  emit('login', { username: username.value.trim(), password: password.value })
}

function onRegister() {
  if (!canSubmit.value) return

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
            <div class="setup-subtitle muted">{{ subtitle }}</div>
          </div>
        </div>

        <div style="margin-left: auto; display: flex; gap: 8px; align-items: center;">
          <button class="secondary" type="button" @click="toggleMode">
            {{ isRegister ? t('signed.login') : t('signed.register') }}
          </button>
        </div>
      </div>

      <form class="setup-form" autocomplete="off" @submit.prevent>
        <label class="field" for="signed-username">
          <span class="field-label">{{ t('signed.username') }}</span>
          <input
            id="signed-username"
            v-model="username"
            maxlength="64"
            inputmode="text"
            :placeholder="String(t('signed.usernamePlaceholder'))"
          />
        </label>

        <label class="field" for="signed-password">
          <span class="field-label">{{ t('signed.password') }}</span>
          <input
            id="signed-password"
            v-model="password"
            type="password"
            minlength="8"
            :placeholder="String(t('signed.passwordPlaceholder'))"
          />
        </label>

        <label v-if="isRegister" class="field" for="signed-exp">
          <span class="field-label">{{ t('signed.expirationDays') }}</span>
          <input id="signed-exp" v-model.number="expirationDays" type="number" min="7" max="365" />
        </label>

        <div class="setup-actions">
          <button v-if="!isRegister" class="join" type="button" :disabled="!canSubmit" @click="onLogin">{{ t('signed.login') }}</button>
          <button v-else class="join" type="button" :disabled="!canSubmit" @click="onRegister">{{ t('signed.register') }}</button>
        </div>

        <div class="setup-header-actions">
          <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
            {{ themeLabel }}
          </button>
          <button class="secondary" type="button" :aria-label="String(t('common.language'))" @click="onCycleLanguage">
            {{ t('common.language') }}: {{ t(`lang.${String(locale)}`) }}
          </button>
          <button class="secondary" type="button" @click="emit('switchAnonymous')">{{ t('signed.switchAnonymous') }}</button>
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
        <div class="modal-title" id="entropyTitle">Entropy</div>
        <div class="muted" style="margin-bottom: 10px;">
          Click 10 times on random places inside the field below.
        </div>
        <div class="muted" style="margin-bottom: 12px;">Hits: {{ entropyHits.length }}/10</div>

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
  </section>
</template>
