#!/usr/bin/env bash
# Generate self-signed certificates for local Caddy development.
# Creates certs/cert.pem and certs/key.pem trusted for localhost.
#
# Usage:
#   bash scripts/generate-local-certs.sh

set -e

CERT_DIR="certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

echo "Generating self-signed certificate for localhost..."

openssl req -x509 -newkey rsa:4096 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 3650 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "✓ Certificate created: $CERT_FILE"
echo "✓ Private key created: $KEY_FILE"
echo ""
echo "Next steps:"
echo "  1. Trust the cert in your browser (visit https://localhost and accept the warning)"
echo "  2. Run: docker compose -f docker-compose.local.yml up -d --build"
