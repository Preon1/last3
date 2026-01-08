<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useToastStore } from '../stores/toast'

const toast = useToastStore()
const { toasts } = storeToRefs(toast)
</script>

<template>
  <div class="toast-host" aria-live="polite" aria-relevant="additions removals">
    <div
      v-for="t in toasts"
      :key="t.id"
      class="toast"
      :class="t.variant === 'error' ? 'toast--error' : 'toast--info'"
      role="status"
    >
      <div class="toast-title">{{ t.title }}</div>
      <div v-if="t.message" class="toast-message">{{ t.message }}</div>
      <button class="btn btn-secondary toast-close" type="button" @click="toast.remove(t.id)">
        ×
      </button>
    </div>
  </div>
</template>
