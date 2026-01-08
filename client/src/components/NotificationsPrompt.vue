<script setup lang="ts">
import { watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useNotificationsStore } from '../stores/notifications'

const props = defineProps<{
  open: boolean
}>()

const emit = defineEmits<{
  (e: 'dismiss'): void
}>()

const notifications = useNotificationsStore()
const { permission, supported } = storeToRefs(notifications)
const { t } = useI18n()

function onBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) emit('dismiss')
}

function onEscape(e: KeyboardEvent) {
  if (e.key === 'Escape') emit('dismiss')
}

async function onEnable() {
  await notifications.requestPermissionAndEnable()
  emit('dismiss')
}

watchEffect((onCleanup) => {
  if (!props.open) return
  document.addEventListener('keydown', onEscape)
  onCleanup(() => document.removeEventListener('keydown', onEscape))
})
</script>

<template>
  <div
    v-if="open"
    class="modal"
    role="dialog"
    aria-modal="true"
    aria-labelledby="notifTitle"
    @click="onBackdropClick"
  >
    <div class="modal-card">
      <div class="modal-title" id="notifTitle">{{ t('notifications.promptTitle') }}</div>

      <div v-if="supported" class="muted">
        <div v-if="permission === 'default'">{{ t('notifications.promptBody') }}</div>
        <div v-else-if="permission === 'denied'">{{ t('notifications.deniedBody') }}</div>
        <div v-else>{{ t('notifications.enabledBody') }}</div>
      </div>
      <div v-else class="muted">{{ t('notifications.unsupportedBody') }}</div>

      <div class="modal-actions">
        <button
          class="secondary"
          type="button"
          :disabled="!supported || permission !== 'default'"
          @click="onEnable"
        >
          {{ t('notifications.enable') }}
        </button>

        <button class="secondary" type="button" @click="emit('dismiss')">{{ t('notifications.notNow') }}</button>
      </div>
    </div>
  </div>
</template>
