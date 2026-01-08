import type { Ref } from 'vue'
import { onBeforeUnmount, watch } from 'vue'

type WakeLockSentinelLike = {
  release: () => Promise<void>
  addEventListener: (type: 'release', listener: () => void) => void
  removeEventListener?: (type: 'release', listener: () => void) => void
}

type NavigatorWakeLockLike = {
  request: (type: 'screen') => Promise<WakeLockSentinelLike>
}

function getWakeLockApi(): NavigatorWakeLockLike | null {
  const anyNav = navigator as unknown as { wakeLock?: NavigatorWakeLockLike }
  return anyNav?.wakeLock ?? null
}

export function useWakeLock(active: Ref<boolean>) {
  let sentinel: WakeLockSentinelLike | null = null

  const onRelease = () => {
    sentinel = null
  }

  async function enableWakeLock() {
    try {
      if (!active.value) return
      if (document.visibilityState !== 'visible') return
      if (sentinel) return

      const api = getWakeLockApi()
      if (!api) return

      sentinel = await api.request('screen')
      sentinel.addEventListener('release', onRelease)
    } catch {
      // ignore
    }
  }

  async function disableWakeLock() {
    try {
      if (sentinel) {
        sentinel.removeEventListener?.('release', onRelease)
        await sentinel.release()
      }
    } catch {
      // ignore
    } finally {
      sentinel = null
    }
  }

  const onVisibility = () => {
    if (document.visibilityState === 'visible') void enableWakeLock()
    else void disableWakeLock()
  }

  document.addEventListener('visibilitychange', onVisibility)

  const stop = watch(
    active,
    (isActive) => {
      if (isActive) void enableWakeLock()
      else void disableWakeLock()
    },
    { immediate: true },
  )

  onBeforeUnmount(() => {
    stop()
    document.removeEventListener('visibilitychange', onVisibility)
    void disableWakeLock()
  })

  return {
    enableWakeLock,
    disableWakeLock,
  }
}
