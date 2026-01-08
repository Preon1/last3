import type { Ref } from 'vue'
import { onBeforeUnmount } from 'vue'

export function useBeforeUnloadConfirm(active: Ref<boolean>) {
  const handler = (e: BeforeUnloadEvent) => {
    if (!active.value) return
    e.preventDefault()
    e.returnValue = ''
    return ''
  }

  window.addEventListener('beforeunload', handler)
  onBeforeUnmount(() => window.removeEventListener('beforeunload', handler))
}
