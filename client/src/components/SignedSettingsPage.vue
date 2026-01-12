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
const { username, hiddenMode, introvertMode } = storeToRefs(signed)

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

async function onDeleteAccount() {
  try {
    const ok = window.confirm(String(t('confirm.deleteAccount', { appName: 'Last' })))
    if (!ok) return
    await signed.deleteAccount()
  } catch {
    // ignore
  }
}

async function onToggleHiddenMode(ev: Event) {
  const target = ev.target as HTMLInputElement | null
  if (!target) return
  try {
    await signed.updateHiddenMode(Boolean(target.checked))
  } catch {
    // ignore
  }
}

async function onToggleIntrovertMode(ev: Event) {
  const target = ev.target as HTMLInputElement | null
  if (!target) return
  try {
    await signed.updateIntrovertMode(Boolean(target.checked))
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
        <div v-if="username">{{ t('signed.youSignedInAs') }} <strong>{{ username }}</strong></div>
      </div>

      <div class="settings-actions">
        <label class="secondary">
          <input
            type="checkbox"
            :checked="Boolean(hiddenMode)"
            @change="onToggleHiddenMode"
            :aria-label="String(t('signed.hiddenMode'))"
          />
          <span>
            <div style="font-weight: 600;">{{ t('signed.hiddenMode') }}</div>
            <div style="opacity: 0.8; font-size: 0.95em;">{{ t('signed.hiddenModeHelp') }}</div>
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
            <div style="font-weight: 600;">{{ t('signed.introvertMode') }}</div>
            <div style="opacity: 0.8; font-size: 0.95em;">{{ t('signed.introvertModeHelp') }}</div>
          </span>
        </label>

        <button class="secondary" type="button" :aria-label="String(t('theme.toggleAria'))" @click="ui.cycleTheme">
          {{ themeLabel }}
        </button>

        <button class="secondary" type="button" :aria-label="String(t('common.language'))" @click="onCycleLanguage">
          {{ t('common.language') }}: {{ t(`lang.${String(locale)}`) }}
        </button>

        <button class="secondary" type="button" @click="onManageKeys">{{ t('common.manageKeys') }}</button>

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
