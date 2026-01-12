const LS_NOTIFICATIONS_ENABLED = 'lrcom-notifications-enabled'

export function getNotificationsEnabled(): boolean {
  try {
    const raw = localStorage.getItem(LS_NOTIFICATIONS_ENABLED)
    if (raw == null) return true
    if (raw === '1' || raw === 'true') return true
    if (raw === '0' || raw === 'false') return false
    return true
  } catch {
    return true
  }
}

export function setNotificationsEnabled(enabled: boolean) {
  try {
    localStorage.setItem(LS_NOTIFICATIONS_ENABLED, enabled ? '1' : '0')
  } catch {
    // ignore
  }
}

export async function closeNotificationsByTag(tag: string) {
  try {
    if (!('serviceWorker' in navigator)) return

    const send = async (sw: ServiceWorker | null | undefined) => {
      try {
        sw?.postMessage({ type: 'closeNotificationByTag', tag })
      } catch {
        // ignore
      }
    }

    if (navigator.serviceWorker.controller) {
      await send(navigator.serviceWorker.controller)
      return
    }

    const reg = await navigator.serviceWorker.ready
    await send(reg.active)
  } catch {
    // ignore
  }
}
