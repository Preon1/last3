<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'

const authStore = useAuthStore()
const { t } = useI18n()
const { view } = storeToRefs(authStore)
</script>

<template>
  <header class="header">
    <div class="header-left">
      <div class="brand"><img class="logo" src="/lrcom_logo.png" alt="" /><span>Last</span></div>
    </div>

    <div class="header-right">
      <button
        v-if="view !== 'settings'"
        class="secondary icon-only"
        type="button"
        :aria-label="String(t('common.settings'))"
        @click="authStore.openSettings"
      >
        <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#filter"></use></svg>
      </button>
    </div>
  </header>
</template>
