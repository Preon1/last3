import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { useSessionStore } from './session'
import { tryEnableWebPushForSocket } from '../utils/push'

export const useNotificationsStore = defineStore('notifications', () => {
  const session = useSessionStore()

  const supported = computed(() => typeof Notification !== 'undefined')
  const permission = ref<NotificationPermission>(typeof Notification === 'undefined' ? 'default' : Notification.permission)
  const didAutoRequestThisSession = ref(false)

  async function requestPermissionAndEnable() {
    if (!supported.value) return false

    try {
      const perm = await Notification.requestPermission()
      permission.value = perm
      if (perm !== 'granted') return false

      // Optional/best-effort.
      return await tryEnableWebPushForSocket(session.send)
    } catch {
      return false
    }
  }

  // Keep permission in sync if browser changes it.
  function refresh() {
    if (!supported.value) return
    permission.value = Notification.permission
  }

  async function autoRequestAfterLogin() {
    if (didAutoRequestThisSession.value) return
    didAutoRequestThisSession.value = true

    if (!supported.value) return
    refresh()
    if (permission.value === 'denied') return

    // Avoid doing anything until the socket is actually usable.
    if (!session.connected) return

    // If already granted, just try enabling push silently.
    // Do NOT request permission here: browsers (esp. mobile) often require a user gesture,
    // and auto-prompts can feel spammy.
    if (permission.value === 'granted') {
      await tryEnableWebPushForSocket(session.send)
    }
  }

  session.registerDisconnectHandler(() => {
    didAutoRequestThisSession.value = false
    refresh()
  })

  return {
    supported,
    permission,
    requestPermissionAndEnable,
    autoRequestAfterLogin,
    refresh,
  }
})
