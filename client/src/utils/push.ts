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

    const expectedKey = urlBase64ToUint8Array(data.publicKey)

    // Only register SW if push is enabled (keeps it quiet when VAPID isn't set).
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' })

    let existing = await reg.pushManager.getSubscription()

    // If server keys changed since this subscription was created, re-subscribe.
    try {
      const curKey = existing?.options?.applicationServerKey
      if (existing && curKey) {
        const cur = new Uint8Array(curKey)
        const exp = expectedKey
        let same = cur.length === exp.length
        if (same) {
          for (let i = 0; i < cur.length; i++) {
            if (cur[i] !== exp[i]) {
              same = false
              break
            }
          }
        }
        if (!same) {
          await existing.unsubscribe().catch(() => {})
          existing = null
        }
      }
    } catch {
      // ignore
    }

    const subscription =
      existing ??
      (await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: expectedKey,
      }))

    return subscription.toJSON()
  } catch {
    return null
  }
}
