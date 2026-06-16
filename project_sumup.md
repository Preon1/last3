# Last Project Sum-Up (AI Agent Guide)

## 1) Project Purpose

Last (previously LRCom Last Resort Communication) is a privacy-first, communication app with:
- Text chat (end-to-end encrypted payloads, client-managed keys).
- Voice calls over WebRTC.
- Optional Web Push for offline message notifications.

Core privacy model:
- No cookie auth.
- Minimal/no logging policy across app and infrastructure.
- Session/auth and call presence are primarily in RAM on the server side.

## 2) Tech Stack and Structure

Monorepo structure:
- client/: Vue 3 + TypeScript + Vite + Pinia SPA.
- server/: Node.js (ESM) + Express + WebTransport (HTTP/3) + PostgreSQL.
- docker-compose.yml: app + Postgres + coturn.
- docker-compose.prod.yml + Caddyfile: production reverse proxy with TLS termination and rate limits.

Important implementation points:
- App serves over HTTPS only (microphone/WebRTC requirement).
- SPA build is produced in client/dist and served by the Node server.
- Signed realtime is hard-cut to WebTransport (no WebSocket fallback).
- Default WebTransport endpoint path is /wt.
- Caddy is optional for production edge TLS and request rate-limiting.

## 3) Main Functional Areas

### 3.1 Signed Authentication and Sessions
- Registration/login uses name tokens + RSA public keys.
- Challenge-response login flow:
	- /api/auth/login-init: server encrypts challenge to stored public key.
	- /api/auth/login-final: client proves private key possession.
- Bearer tokens are in-memory (authSession.js), rotated via /api/session/refresh.
- Multi-device sessions supported with eviction and forced logout notifications.

### 3.2 VOPRF-Based Name Tokens
- Server exposes /api/config and /api/voprf/eval for VOPRF blind evaluation.
- Name tokens are opaque outputs (no plain username leakage in server DB logic).

### 3.3 Signed Chat System
- Personal and group chats.
- Chat membership and visibility enforced in SQL layer.
- Endpoints for:
	- chat listing, creation, rename, membership changes
	- message send/update/delete/read/unread
	- account settings and account deletion
- Server sends realtime events over WebTransport (reliable control stream + datagram lane).

### 3.4 Voice Calling
- WebRTC media is P2P; server handles signaling via WebTransport reliable control messages.
- In-memory signed call rooms with:
	- call start/accept/reject/hangup
	- join request queue for busy calls
	- per-session control to avoid duplicate actions from multiple tabs/devices
- TURN credentials are time-limited and generated server-side from shared secret.

### 3.5 Notifications and Push
- In-tab notifications via client utility.
- Optional Web Push with VAPID keys.
- Push subscriptions and queue state are DB-backed.
- Push dispatch is skipped for users currently online.

### 3.6 Data Lifecycle and Cleanup
- Periodic cleanup of expired users.
- Account delete and cleanup routines scrub user recipient wrappers from encrypted envelopes before and during deletion cascades.
- Chat cleanup removes invalid/empty chats after membership changes.

### 3.7 I18n and PWA Behavior
- Locales: en, nl, fr, de, ru.
- Missing locale keys are deep-merged from English fallback.
- PWA/service worker integration includes resume sync behavior and notification-state coordination.

## 4) Architecture and Coding Approaches

### 4.1 Security/Privacy-First Defaults
- Keep responses generic for auth failures (avoid sensitive detail leakage).
- Avoid logging user-sensitive data.
- Prefer no-store for dynamic/security-sensitive endpoints.
- Use strict security headers and tight CSP.

### 4.2 Realtime Reliability Pattern
- Two transport send modes:
	- datagram best-effort for heartbeat/presence events.
	- reliable control stream (msgId + ack + retry loop) for control-plane events like forced logout.
- Client message id receipts are cached for idempotency/replay-safe handling.

### 4.3 Explicit Input Validation
- Validate all request fields and types early.
- Enforce payload size limits (example: encrypted message byte cap).
- Return explicit HTTP statuses for forbidden/not_found/bad_request cases.

### 4.4 Clear Separation of Responsibilities
- server/index.js orchestrates API + WebTransport flows.
- server/authDb.js contains signed chat/message data logic.
- server/authSession.js owns in-memory token/session handling.
- client/stores/signed.ts is the central signed app state coordinator.
- client/stores/call.ts isolates call state machine and media handling.

### 4.5 Defensive Error Handling Style
- Broad use of try/catch with silent fallback where failure is non-critical.
- Critical failures fail fast (startup checks for TLS/build artifacts/DB).
- Best-effort background jobs (cleanup/push) should not crash the process.

## 5) Coding Rules for Future AI Agents

Follow these project rules when changing code.

0. Do not bother with DB migrations, project is under development. Just update the initial DB structure.

1. Preserve privacy policy behavior.
- Do not add verbose logging, analytics, or tracking.
- Do not emit user content/keys/tokens to logs.

2. Keep HTTPS and secure-context assumptions intact.
- Do not introduce HTTP fallback paths for core app use.
- Respect TLS-related startup constraints and deployment model.

3. Maintain auth/session model consistency.
- Keep bearer-token, no-cookie approach.
- Respect in-memory session semantics and session eviction behavior.

4. Keep signed message data opaque.
- Treat encryptedData/signature as client-originated cryptographic payloads.
- Do not add server-side plaintext handling.

5. Respect strict request validation.
- Add field/type/length checks for any new endpoint.
- Use existing error-shape conventions ({ error: '...' } / { success: true, ... }).

6. Keep realtime semantics backward-compatible.
- New realtime message types should be additive.
- Preserve existing ack/msgId/receipt behaviors across reliable stream messaging.
- Be careful with multi-session control paths.

7. Enforce authorization at data boundaries.
- Check membership/ownership before read/write actions.
- Keep introvert/hidden mode behavior consistent when extending related features.

8. Use the established persistence abstraction in client.
- Access browser persistence through localData helpers.
- Keep cleanup semantics for logout/logout_wipe/account_delete.

9. Keep TypeScript strictness and current style.
- Do not weaken tsconfig strict options.
- Prefer explicit types and small helper functions for runtime guards.

10. Avoid unnecessary dependencies/framework changes.
- Reuse existing stack and utility modules.
- Keep Docker/Caddy/Postgres/coturn integration assumptions unchanged unless explicitly requested.

11. Protect operational stability.
- Background loops should be idempotent and failure-tolerant.
- Do not block startup or request paths with expensive synchronous work.

12. Preserve API and migration compatibility.
- Do not break existing endpoint contracts without coordinated client updates.
- For DB changes, add migration scripts and keep old data readable.

13. Do not use "signed" word in any naming unless absolutely nessesary, like it means some sort of crypto signature. Its a legacy word in a project, since it wasn't utilizing user registration before.

## 6) Quick Agent Onboarding Checklist

Before coding:
- Read server/index.js, server/authDb.js, client/src/stores/signed.ts, client/src/stores/call.ts.
- Confirm if change touches security/privacy, auth/session, WebTransport signaling, or DB schema.

During coding:
- Keep modifications minimal and scoped.
- Mirror existing naming, response format, and fallback/error style.
- Add migration when altering DB schema.

Before finishing:
- Build client: npm run build (client/).
- Ensure changed endpoints and realtime message flows still match client usage.
- Re-check for accidental logs or plaintext-sensitive data exposure.

## 7) High-Risk Areas (Handle Carefully)

- WebTransport call signaling state machine and multi-session control.
- Session rotation/eviction/forced logout flows.
- Message visibility/read/unread semantics and member boundaries.
- Account deletion and encrypted envelope scrubbing logic.
- Push queue behavior and stale subscription cleanup.

## 8) Current Transport/Env Defaults

- WebTransport path: /wt
- Local default endpoint: https://localhost:8444/wt
- Runtime defaults in app container:
	- WEBTRANSPORT_ENABLED=1
	- WEBTRANSPORT_HOST=0.0.0.0
	- WEBTRANSPORT_PORT=8444
	- WEBTRANSPORT_PATH=/wt
- Local compose publishes:
	- 8443/tcp (app HTTPS)
	- 8444/udp (WebTransport)
- Prod compose also publishes:
	- 443/udp (HTTP/3 edge on Caddy)
	- 8444/udp (direct WebTransport endpoint)
