<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'

const emit = defineEmits<{ (e: 'logout'): void }>()

const ui = useUiStore()
const signed = useSignedStore()

const { themeLabel } = storeToRefs(ui)
const { username } = storeToRefs(signed)
const { t } = useI18n()

const password = ref('')
const busy = ref(false)
const err = ref('')

const canSubmit = computed(() => Boolean(password.value))

async function onUnlock() {
  err.value = ''
  if (!canSubmit.value) return
  busy.value = true
  try {
    await signed.unlock({ password: password.value })
    password.value = ''
  } catch (e: any) {
    err.value = typeof e?.message === 'string' ? e.message : String(t('signed.unlockFailed'))
  } finally {
    busy.value = false
  }
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
            <div class="setup-subtitle muted">{{ t('signed.unlockSubtitle') }}</div>
          </div>
        </div>
      </div>

      <form class="setup-form" autocomplete="off" @submit.prevent="onUnlock">
        <div class="status">
          {{ t('signed.unlockFor') }} <strong>{{ username ?? '' }}</strong>
        </div>

        <label class="field" for="signed-unlock-password">
          <span class="field-label">{{ t('signed.password') }}</span>
          <input
            id="signed-unlock-password"
            v-model="password"
            type="password"
            minlength="8"
            :placeholder="String(t('signed.passwordPlaceholder'))"
          />
        </label>

        <button class="join" type="submit" :disabled="busy || !canSubmit">{{ t('signed.unlock') }}</button>

        <div v-if="err" class="status" aria-live="polite">{{ err }}</div>

        <div class="setup-header-actions">
          <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
            {{ themeLabel }}
          </button>
          <button class="secondary" type="button" @click="emit('logout')">{{ t('common.logout') }}</button>
        </div>
      </form>
    </div>
  </section>
</template>
