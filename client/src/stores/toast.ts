import { defineStore } from 'pinia'
import { ref } from 'vue'

export type ToastVariant = 'info' | 'error'

export type ToastItem = {
  id: string
  title: string
  message?: string
  variant: ToastVariant
  timeoutMs: number
}

function makeId() {
  try {
    if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID()
  } catch {
    // ignore
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

export const useToastStore = defineStore('toast', () => {
  const toasts = ref<ToastItem[]>([])

  function remove(id: string) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }

  function push(toast: Omit<ToastItem, 'id'>) {
    const id = makeId()
    const item: ToastItem = { id, ...toast }
    toasts.value = [...toasts.value, item]

    window.setTimeout(() => {
      remove(id)
    }, item.timeoutMs)

    return id
  }

  function error(title: string, message?: string, timeoutMs = 6000) {
    return push({ title, message, variant: 'error', timeoutMs })
  }

  return { toasts, push, remove, error }
})
