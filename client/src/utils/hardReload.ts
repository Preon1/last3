export async function hardReloadApp(): Promise<void> {
  // Best-effort: clear SW + caches, then navigate with a cache-busting param.
  // This is intended for installed PWAs where the user has no browser UI.
  try {
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations().catch(() => [])
      await Promise.all(
        regs.map(async (r) => {
          try {
            await r.unregister()
          } catch {
            // ignore
          }
        }),
      )
    }

    if ('caches' in window) {
      const keys = await caches.keys().catch(() => [])
      await Promise.all(
        keys.map(async (k) => {
          try {
            await caches.delete(k)
          } catch {
            // ignore
          }
        }),
      )
    }
  } catch {
    // ignore
  }

  try {
    const url = new URL(window.location.href)
    url.searchParams.set('_reload', Date.now().toString(36))
    window.location.replace(url.toString())
  } catch {
    try {
      window.location.reload()
    } catch {
      // ignore
    }
  }
}
