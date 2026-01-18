import { LocalEntity, localData } from './localData'

export function getNotificationsEnabled(): boolean {
  return localData.getBool(LocalEntity.NotificationsEnabled, false)
}

export function setNotificationsEnabled(enabled: boolean) {
  localData.setBool(LocalEntity.NotificationsEnabled, Boolean(enabled))
}

export function getPushNotificationsEnabled(): boolean {
  return localData.getBool(LocalEntity.PushNotificationsEnabled, false)
}

export function setPushNotificationsEnabled(enabled: boolean) {
  localData.setBool(LocalEntity.PushNotificationsEnabled, Boolean(enabled))
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

export async function closeAllNotifications() {
  try {
    if (!('serviceWorker' in navigator)) return

    const send = async (sw: ServiceWorker | null | undefined) => {
      try {
        sw?.postMessage({ type: 'closeAllNotifications' })
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

export async function broadcastAppStateToServiceWorker(state: { foreground: boolean; view: string }) {
  try {
    if (!('serviceWorker' in navigator)) return
    const msg = { type: 'appState', foreground: Boolean(state.foreground), view: String(state.view || '') }

    const send = async (sw: ServiceWorker | null | undefined) => {
      try {
        sw?.postMessage(msg)
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
