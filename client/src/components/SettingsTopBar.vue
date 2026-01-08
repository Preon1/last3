<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <div class="chat-topbar" role="region" :aria-label="String(t('settings.title'))">
    <div class="chat-topbar-left">
      <div class="chat-topbar-title">{{ t('settings.title') }}</div>
    </div>
  </div>
</template>
