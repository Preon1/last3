<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'

const signed = useSignedStore()
const { t } = useI18n()

type ModalMode = 'connectionLost' | 'authorizationLost'

const mode = computed<ModalMode | null>(() => {
  if (!signed.signedIn) return null
  if (signed.authorizationLost) return 'authorizationLost'
  if (signed.wsPermanentlyFailed) return 'connectionLost'
  return null
})

const open = computed(() => Boolean(mode.value))

const titleKey = computed(() => {
  return mode.value === 'authorizationLost' ? 'signed.authorizationLost.title' : 'signed.connectionLost.title'
})

const bodyKey = computed(() => {
  return mode.value === 'authorizationLost' ? 'signed.authorizationLost.body' : 'signed.connectionLost.body'
})

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
  <div v-if="open" class="modal" role="dialog" aria-modal="true" :aria-label="t(titleKey)">
    <div class="modal-backdrop" />

    <div class="modal-card">
      <div class="modal-title">{{ t(titleKey) }}</div>
      <div class="modal-body">
        {{ t(bodyKey) }}
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
