<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useUiStore } from '../stores/ui'
import { useI18n } from 'vue-i18n'
import { cycleLocale } from '../i18n'

defineProps<{ status: string }>()

const emit = defineEmits<{ (e: 'join', name: string): void }>()

const ui = useUiStore()
const { themeLabel } = storeToRefs(ui)

const { t, locale } = useI18n()

const languageLabel = computed(() => {
  const key = `lang.${String(locale.value)}`
  return String(t(key))
})

function onCycleLanguage() {
  cycleLocale()
}

const nameInput = ref('')

function onJoin() {
  const trimmed = nameInput.value.trim()
  if (!trimmed) return
  emit('join', trimmed)
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
            <div class="setup-subtitle muted">{{ t('setup.subtitle') }}</div>
          </div>
        </div>
      </div>

      <form class="setup-form" autocomplete="off" @submit.prevent="onJoin">
        <label class="field" for="name">
          <span class="field-label">{{ t('setup.yourName') }}</span>
          <input
            id="name"
            v-model="nameInput"
            maxlength="20"
            inputmode="text"
            :placeholder="String(t('setup.namePlaceholder'))"
          />
        </label>

        <button class="join" type="submit">{{ t('setup.join') }}</button>

        <div class="status" aria-live="polite">{{ status }}</div>

        <div class="setup-header-actions">
          <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
            {{ themeLabel }}
          </button>
          <button
            class="secondary"
            type="button"
            :aria-label="String(t('common.language'))"
            @click="onCycleLanguage"
          >
            {{ t('common.language') }}: {{ languageLabel }}
          </button>
          <button class="secondary" type="button" :aria-label="String(t('common.about'))" @click="ui.openAbout">
            {{ t('common.about') }}
          </button>
        </div>
      </form>
    </div>
  </section>
</template>
