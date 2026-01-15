<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSignedStore } from '../stores/signed'
import { hardReloadApp } from '../utils/hardReload'

const signed = useSignedStore()
const { t } = useI18n()

const open = computed(() => Boolean((signed.wsPermanentlyFailed && signed.signedIn) || signed.serverUpdateModalOpen))

const isServerUpdate = computed(() => Boolean(signed.serverUpdateModalOpen))

const updateBody = computed(() => {
  const from = signed.serverUpdatedFrom || ''
  const to = signed.serverUpdatedTo || ''
  if (!from || !to) return 'Server has been updated. Application should be reloaded now or later in settings.'
  return `Server has been updated from ${from} to ${to}. Application should be reloaded now or later in settings.`
})

function onReload() {
  void hardReloadApp()
}

function onClose() {
  try {
    signed.dismissServerUpdateModal()
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
  <div v-if="open" class="modal" role="dialog" aria-modal="true" :aria-label="isServerUpdate ? 'Update available' : t('signed.connectionLost.title')">
    <div class="modal-backdrop" />

    <div class="modal-card">
      <div class="modal-title">{{ isServerUpdate ? 'Update available' : t('signed.connectionLost.title') }}</div>
      <div class="modal-body">
        {{ isServerUpdate ? updateBody : t('signed.connectionLost.body') }}
      </div>

      <div class="modal-actions">
        <button v-if="!isServerUpdate" class="btn" @click="onLogout">{{ t('common.logout') }}</button>
        <button v-else class="btn" @click="onClose">{{ t('common.close') }}</button>
        <button class="btn primary" @click="onReload">{{ t('signed.reloadAppNoCache') }}</button>
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
