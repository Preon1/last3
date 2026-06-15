<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'
import { hardReloadApp } from '../utils/hardReload'

const authStore = useAuthStore()
const { t } = useI18n()

const open = computed(() => Boolean((authStore.wsPermanentlyFailed && authStore.authIn) || authStore.serverUpdateModalOpen))

const isServerUpdate = computed(() => Boolean(authStore.serverUpdateModalOpen))

const updateBody = computed(() => {
  const from = authStore.serverUpdatedFrom || ''
  const to = authStore.serverUpdatedTo || ''
  if (!from || !to) return String(t('serverUpdate.bodyGeneric'))
  return String(t('serverUpdate.bodyFromTo', { from, to }))
})

const connectionLostBody = computed(() => {
  const reason = String(authStore.transportFatalReason || '').trim()
  if (!reason) return String(t('connectionLost.body'))
  return `${String(t('connectionLost.body'))}\n\n${reason}`
})

function onReload() {
  void hardReloadApp()
}

function onClose() {
  try {
    authStore.dismissServerUpdateModal()
  } catch {
    // ignore
  }
}

function onLogout() {
  try {
    authStore.logout(true)
  } catch {
    // ignore
  }
}
</script>

<template>
  <div
    v-if="open"
    class="modal"
    role="dialog"
    aria-modal="true"
    :aria-label="isServerUpdate ? t('serverUpdate.title') : t('connectionLost.title')"
  >
    <div class="modal-backdrop" />

    <div class="modal-card">
      <div class="modal-title">{{ isServerUpdate ? t('serverUpdate.title') : t('connectionLost.title') }}</div>
      <div class="modal-body">
        {{ isServerUpdate ? updateBody : connectionLostBody }}
      </div>

      <div class="modal-actions">
        <button v-if="!isServerUpdate" class="btn" @click="onLogout">{{ t('common.logout') }}</button>
        <button v-else class="btn" @click="onClose">{{ t('common.close') }}</button>
        <button class="btn primary" @click="onReload">{{ t('reloadAppNoCache') }}</button>
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
