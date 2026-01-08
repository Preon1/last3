<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { cycleLocale } from '../i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'
import { confirmLeave } from '../utils/confirmLeave'

const ui = useUiStore()
const signed = useSignedStore()
const { t, locale } = useI18n()

const { themeLabel } = storeToRefs(ui)
const { username } = storeToRefs(signed)

function onCycleLanguage() {
  cycleLocale()
}

function onAbout() {
  ui.openAbout()
}

function onLogout() {
  if (!confirmLeave('Last')) return
  signed.logout(true)
}

async function onDeleteAccount() {
  try {
    const ok = window.confirm(String(t('confirm.deleteAccount', { appName: 'Last' })))
    if (!ok) return
    await signed.deleteAccount()
  } catch {
    // ignore
  }
}
</script>

<template>
  <section class="page">
    <div class="page-inner">
      <div class="headergap"></div>

      <div class="settings-tech">
        <div v-if="username" class="status">{{ t('signed.youSignedInAs') }} <strong>{{ username }}</strong></div>
      </div>

      <div class="settings-actions">
        <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
          {{ themeLabel }}
        </button>

        <button class="secondary" type="button" :aria-label="String(t('common.language'))" @click="onCycleLanguage">
          {{ t('common.language') }}: {{ t(`lang.${String(locale)}`) }}
        </button>

        <button class="secondary" type="button" @click="onAbout">{{ t('common.about') }}</button>

        <button class="secondary" type="button" @click="onDeleteAccount">{{ t('signed.deleteAccount') }}</button>

        <button
          class="secondary icon-only"
          type="button"
          :aria-label="String(t('common.logout'))"
          :title="String(t('common.logout'))"
          @click="onLogout"
        >
          <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#logout"></use></svg>
        </button>
      </div>
    </div>
  </section>
</template>
