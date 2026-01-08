# Last (Last Resort Communication)

Minimal ephemeral voice chat: open the page, enter a name, see online users, click to call, accept/reject incoming calls.

**Privacy model**: No registration, no cookies, no persistent sessions. Server keeps only in-memory presence while your WebSocket is connected. When you close the tab, your name disappears.

## How it works

- Audio uses **WebRTC** (Opus) between browsers.
- The server only does **signaling** (WebSocket) + presence.
- Media is encrypted by WebRTC (**DTLS-SRTP**).

## Important: HTTPS for microphone

Browsers only allow `getUserMedia()` (microphone) in a **secure context**:
- `https://...`

This repo is now **HTTPS-only** (no HTTP mode).

## Run (prod-like, single supported mode)

From this folder:

1) Create a `.env` file (recommended for Internet use):

- Copy `.env.example` to `.env` and fill in `LRCOM_TURN_HOST`, `LRCOM_TURN_SECRET`, and `LRCOM_TURN_EXTERNAL_IP`.

2) Start (builds the client and serves it from the Node server over HTTPS):

```bash
docker compose up --build
```

Then open:

- Local machine: `https://localhost:8443`

Only one port is used: `8443`.

## Production install (Ubuntu 24 + rootless Docker + domain + Let's Encrypt RSA-4096)

This repo includes a production reverse proxy setup using:

- [docker-compose.prod.yml](docker-compose.prod.yml) (Caddy reverse proxy)
- [Caddyfile](Caddyfile) (automatic Let's Encrypt TLS with RSA 4096)

The app container still serves HTTPS internally on `8443`. Caddy terminates public HTTPS on `443` and proxies to the app.

### 1) Prereqs

- Clean Ubuntu 24 server
- Docker installed in **rootless** mode for your deployment user
- A domain name pointing to the server (DNS A/AAAA)

### 2) Open required ports

On your server/firewall/router/cloud rules, allow:

- `80/tcp` (Let's Encrypt HTTP-01 + redirect)
- `443/tcp` (HTTPS)
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

TURN must be reachable by browsers:

- `LRCOM_TURN_HOST=your.domain.com` (or your public IP)
- `LRCOM_TURN_SECRET=...` (long random string)
- `LRCOM_TURN_EXTERNAL_IP=your.public.ip`

### 5) Start

Run the production stack (base compose + prod override):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Open:

- `https://your.domain.com`

### Notes

- Certificates auto-renew via Caddy.
- TLS key type is configured as **RSA 4096** in [Caddyfile](Caddyfile).
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

- WebRTC encrypts media, but you still must protect **signaling** with HTTPS/WSS to reduce MITM risk.
- This project intentionally does not log calls or store user data.
- Names are limited to simple characters and must be unique while online.

## Limitations

- No user authentication (by design).
- No identity verification beyond TLS to the server (so don’t treat the displayed name as strongly authenticated).
