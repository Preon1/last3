# Client (Vue 3 + Vite)

This folder contains the new client-side SPA that will replace `server/public` over time.

## Dev

1) Start the backend (recommended: docker compose)

- From repo root: `docker compose up -d --build`

2) Start the Vite dev server

- From `client/`: `npm run dev`
- Open: http://localhost:5173/

### Backend proxy

- HTTP endpoints (`/api/*`, `/turn`, `/healthz`) are proxied to the backend.
- Signed realtime uses browser WebTransport directly (not via Vite proxy).
	- Default endpoint: `https://localhost:8444/wt`
	- Override via `VITE_WEBTRANSPORT_URL`.

If your backend is not on `https://localhost:8443`, override in `client/.env.development`:

- `VITE_BACKEND_TARGET=https://your-host:8443`
- `VITE_WEBTRANSPORT_URL=https://your-host:8444/wt`

## Build

- `npm run build`

Integration (serving the built SPA from the Node server) will be added once feature parity is reached.
