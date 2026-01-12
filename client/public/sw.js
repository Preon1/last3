self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

let lastAppState = null;

self.addEventListener('push', (event) => {
  // Best-effort suppression: if the app told us it's foregrounded (any view),
  // skip system notifications (user is already looking at the app).
  try {
    if (lastAppState && lastAppState.foreground === true) {
      return;
    }
  } catch {
    // ignore
  }

  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    try {
      data = { body: event.data ? event.data.text() : '' };
    } catch {
      data = {};
    }
  }

  const title = data.title || 'Last';
  const body = data.body || '';
  const tag = data.tag || 'last';
  const url = data.url || '/';
  const requireInteraction = Boolean(data.requireInteraction);
  const vibrate = Array.isArray(data.vibrate) ? data.vibrate : [200, 100, 200];

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag,
      renotify: true,
      requireInteraction,
      vibrate,
      icon: './web-app-manifest-192x192.png',
      badge: './web-app-manifest-192x192.png',
      data: { url },
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification?.data?.url || '/';

  event.waitUntil(
    (async () => {
      const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const client of allClients) {
        if ('focus' in client) {
          client.navigate(url);
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
      return undefined;
    })(),
  );
});

self.addEventListener('message', (event) => {
  const data = event?.data || {};
  if (!data || typeof data.type !== 'string') return;

  if (data.type === 'appState') {
    const foreground = Boolean(data.foreground);
    const view = typeof data.view === 'string' ? data.view : '';
    lastAppState = { foreground, view };
    return;
  }

  if (data.type === 'closeNotificationByTag') {
    const tag = typeof data.tag === 'string' ? data.tag : '';
    if (!tag) return;

    event.waitUntil(
      (async () => {
        try {
          const list = await self.registration.getNotifications({ tag });
          for (const n of list) {
            try {
              n.close();
            } catch {
              // ignore
            }
          }
        } catch {
          // ignore
        }
      })(),
    );
  }

  if (data.type === 'closeAllNotifications') {
    event.waitUntil(
      (async () => {
        try {
          const list = await self.registration.getNotifications({});
          for (const n of list) {
            try {
              n.close();
            } catch {
              // ignore
            }
          }
        } catch {
          // ignore
        }
      })(),
    );
  }
});
