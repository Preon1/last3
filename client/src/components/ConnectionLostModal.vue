<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'

const signed = useSignedStore()
const { t } = useI18n()

const open = computed(() => Boolean(signed.wsPermanentlyFailed && signed.signedIn))

function onReload() {
  try {
    location.reload()
  } catch {
    // ignore
  }
}

function onLogout() {
  try {
    signed.logout(true)
  } catch {
    // ignore
  }
}
</script>

<template>
  <div v-if="open" class="modal" role="dialog" aria-modal="true" :aria-label="t('signed.connectionLost.title')">
    <div class="modal-backdrop" />

    <div class="modal-card">
      <div class="modal-title">{{ t('signed.connectionLost.title') }}</div>
      <div class="modal-body">
        {{ t('signed.connectionLost.body') }}
      </div>

      <div class="modal-actions">
        <button class="btn" @click="onLogout">{{ t('common.logout') }}</button>
        <button class="btn primary" @click="onReload">{{ t('common.reload') }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.modal {
  z-index: 50;
}
.modal-backdrop{
  position: absolute;
}
</style>
