# Last (Last Resort Communication)

Minimal ephemeral voice chat: open the page, enter a name, see online users, click to call, accept/reject incoming calls.

**Privacy model**: No registration, no cookies, no persistent sessions. Server keeps only in-memory presence while your WebTransport session is connected. When you close the tab, your name disappears.

## How it works

- Audio uses **WebRTC** (Opus) between browsers.
- The server only does **signaling** over WebTransport + presence.
- Media is encrypted by WebRTC (**DTLS-SRTP**).

## Important: HTTPS for microphone

Browsers only allow `getUserMedia()` (microphone) in a **secure context**:
- `https://...`

This repo is now **HTTPS-only** (no HTTP mode).

## Local Development

The recommended way to develop and test locally uses Caddy with self-signed certificates, full logging, and relaxed rate limits.

### 1) Generate self-signed certificates

# Bash (Linux/macOS)
bash scripts/generate-local-certs.sh
```

This creates `certs/cert.pem` and `certs/key.pem` for `localhost` / `127.0.0.1`.

### 2) Start the local stack

```bash
docker compose -f docker-compose.local.yml up -d --build
```

Then open:

- App: `https://localhost` (Caddy on port 443)
- Direct app (bypass Caddy): `https://localhost:8443`
- WebTransport: `https://localhost:8444/wt`

### 3) Trust the certificate

On first visit, your browser will show a certificate warning. Accept it to trust the self-signed cert for this session.

### Local vs Production configs

| Config | Local (`docker-compose.local.yml`) | Production (`docker-compose.prod.yml`) |
|---|---|---|
| Caddy config | `Caddyfile.local` | `Caddyfile.prod` |
| TLS | Self-signed (generated) | Let's Encrypt (RSA 4096) |
| Logging | Full (DEBUG level, DB logs on) | Minimal (logs discarded) |
| Rate limits | Relaxed for testing | Strict production defaults |
| Caddy port | 443 (HTTPS + HTTP/3) | 443 (HTTPS + HTTP/3) |

## Run (standalone, no Caddy)

From this folder:

1) Create a `.env` file (recommended for Internet use):

- Copy `.env.example` to `.env` and fill in `LRCOM_TURN_HOST`, `LRCOM_TURN_SECRET`, and `LRCOM_TURN_EXTERNAL_IP`.

2) Start (builds the client and serves it from the Node server over HTTPS):

Then open:

- Local machine: `https://localhost:8443`

Realtime WebTransport (QUIC/UDP) defaults to:

- `https://localhost:8444/wt`

Default local ports:

- `8443/tcp` app HTTPS
- `8444/udp` WebTransport

## Production install (Ubuntu 24 + rootless Docker + domain + Let's Encrypt RSA-4096)

This repo includes a production reverse proxy setup using:

- [docker-compose.prod.yml](docker-compose.prod.yml) (Caddy reverse proxy)
- [Caddyfile.prod](Caddyfile.prod) (automatic Let's Encrypt TLS with RSA 4096)

The app container still serves HTTPS internally on `8443`. Caddy terminates public HTTPS on `443` and proxies to the app.

### 1) Prereqs

- Clean Ubuntu 24 server
- Docker installed in **rootless** mode for your deployment user
- A domain name pointing to the server (DNS A/AAAA)

### 2) Open required ports

On your server/firewall/router/cloud rules, allow:

- `80/tcp` (Let's Encrypt HTTP-01 + redirect)
- `443/tcp` (HTTPS)
- `443/udp` (HTTP/3)
- `8444/udp` (direct WebTransport endpoint)
- `3478/tcp` and `3478/udp` (TURN)
- `49160-49200/udp` (TURN relay range; configurable)

### 3) Rootless Docker: allow binding to 80/443 (persistent)

Rootless Docker uses RootlessKit for port forwarding. To publish ports `80`/`443`, set `net.ipv4.ip_unprivileged_port_start=80`.

Create a sysctl drop-in (persistent across reboots):

```bash
sudo tee /etc/sysctl.d/99-rootless-ports.conf >/dev/null <<'EOF'
net.ipv4.ip_unprivileged_port_start=80
EOF
sudo sysctl --system
```

Verify:

```bash
sysctl net.ipv4.ip_unprivileged_port_start
```

Restart rootless Docker (so RootlessKit picks it up):

```bash
systemctl --user restart docker
```

### 4) Configure `.env`

Copy `.env.example` to `.env` and set at least:

- `LRCOM_DOMAIN=your.domain.com` (required for Caddy)
- `ACME_EMAIL=you@your.domain.com` (recommended for Let's Encrypt)

WebTransport defaults:

- `WEBTRANSPORT_PORT=8444`
- `VITE_WEBTRANSPORT_URL=https://your.domain.com:8444/wt`

TURN must be reachable by browsers:

- `LRCOM_TURN_HOST=your.domain.com` (or your public IP)
- `LRCOM_TURN_SECRET=...` (long random string)
- `LRCOM_TURN_EXTERNAL_IP=your.public.ip`

### 5) Start

Run the production stack (base compose + prod override):

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Open:

- `https://your.domain.com`

### Notes

- Certificates auto-renew via Caddy.
- TLS key type is configured as **RSA 4096** in [Caddyfile.prod](Caddyfile.prod).
- The app is proxied over internal HTTPS; Caddy is configured to skip TLS verification for that internal hop because the app uses a self-signed cert by default.

## HTTPS (default)

By default, the container generates a **self-signed** certificate (personal/private use). Your browser will show a warning unless you add the cert to your trust store.

If you want a “clean” trusted setup, put Last behind a proper reverse proxy with a real certificate.

### Using your own cert

Provide a key+cert and set env vars:

- `TLS_KEY_PATH=/certs/key.pem`
- `TLS_CERT_PATH=/certs/cert.pem`

Example compose override:

```yaml
services:
  lrcom:
    volumes:
      - ./certs:/certs:ro
    environment:
      - AUTO_TLS=0
      - TLS_KEY_PATH=/certs/key.pem
      - TLS_CERT_PATH=/certs/cert.pem
```

### LAN access (important)

If you access Last via your LAN IP (e.g. `https://192.168.1.50:8443`), the certificate must include that IP in **SANs**.

Set (Windows example):

```bash
setx LRCOM_TLS_SANS "DNS:localhost,IP:127.0.0.1,IP:192.168.1.50"
```

## TURN server

`docker-compose.yml` includes a coturn service for NAT traversal. Last generates time-limited TURN credentials from `TURN_SECRET`.

Set these env vars (recommended):

- `LRCOM_TURN_SECRET`: shared secret used by both Last and coturn
- `LRCOM_TURN_HOST`: hostname/IP that browsers should use to reach TURN (e.g. `localhost`, your LAN IP, or your domain)
- `LRCOM_TURN_EXTERNAL_IP`: often required when coturn runs in Docker so relay addresses are reachable (set to your host LAN/public IP)

Example:

```bash
setx LRCOM_TURN_SECRET "a-strong-random-secret"
setx LRCOM_TURN_HOST "192.168.1.50"
setx LRCOM_TURN_EXTERNAL_IP "192.168.1.50"
```

### If you can only open ~10 UDP ports

TURN needs a relay port range for media. This repo defaults to **10 UDP relay ports**:

- `49160-49169/udp`

You can change it:

```bash
setx LRCOM_TURN_MIN_PORT "49160"
setx LRCOM_TURN_MAX_PORT "49169"
```

Tradeoff: fewer relay ports means fewer simultaneous TURN-relayed calls. Rough rule of thumb: a 2-person call typically consumes ~2 relay ports total (one per participant), so 10 ports supports about ~5 concurrent calls that require TURN.

## Security notes (practical)

- WebRTC encrypts media, but you still must protect **signaling** with HTTPS/HTTP3 to reduce MITM risk.
- This project intentionally does not log calls or store user data.
- Names are limited to simple characters and must be unique while online.

## Limitations

- No user authentication (by design).
- No identity verification beyond TLS to the server (so don’t treat the displayed name as strongly authenticated).

## Admin: delete a signed user (CLI)

If you need to remove a signed user from the server (same effect as the user clicking **Settings → Delete account**), you can run:

```bash
cd server

# Show help
node scripts/delete-user.js --help

# Dry run (no DB changes)
node scripts/delete-user.js --username alice --dry-run

# Delete (asks for confirmation: type 'yes')
node scripts/delete-user.js --username alice

# Delete without prompt
node scripts/delete-user.js --username alice --yes
```

Notes:

- This performs the same DB deletion as the in-app flow (`signedDeleteAccount`).
- If the main server process is currently running, any in-memory session/transport state for that user can persist until restart. Restart the server if you need to force-disconnect/revoke RAM-only state.
