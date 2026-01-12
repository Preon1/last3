function urlBase64ToUint8Array(base64String: string) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4)
  const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/')
  const rawData = atob(base64)
  return Uint8Array.from([...rawData].map((c) => c.charCodeAt(0)))
}

export async function tryGetWebPushSubscriptionJson() {
  try {
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return null
    if (!('serviceWorker' in navigator)) return null
    if (!('PushManager' in window)) return null

    const res = await fetch('/api/push/public-key', { cache: 'no-store' })
    if (!res.ok) return null
    const data = (await res.json()) as { enabled?: boolean; publicKey?: string }
    if (!data?.enabled || !data?.publicKey) return null

    // Only register SW if push is enabled (keeps it quiet when VAPID isn't set).
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' })

    const existing = await reg.pushManager.getSubscription()
    const subscription =
      existing ??
      (await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(data.publicKey),
      }))

    return subscription.toJSON()
  } catch {
    return null
  }
}
