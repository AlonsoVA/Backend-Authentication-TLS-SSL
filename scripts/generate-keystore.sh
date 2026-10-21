#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/src/main/resources/keystore/dev-keystore.p12}"
PASS="${SSL_KEY_STORE_PASSWORD:-dev-local-changeit}"

mkdir -p "$(dirname "$OUT")"

if [[ -f "$OUT" && "${FORCE:-0}" != "1" ]]; then
  echo "El keystore ya existe: $OUT"
  echo "Use FORCE=1 para regenerarlo."
  exit 0
fi

rm -f "$OUT"

keytool -genkeypair \
  -alias backend-tls \
  -keyalg RSA \
  -keysize 2048 \
  -sigalg SHA256withRSA \
  -storetype PKCS12 \
  -keystore "$OUT" \
  -validity 3650 \
  -storepass "$PASS" \
  -keypass "$PASS" \
  -dname "CN=localhost, OU=HU-SEC-001, O=Trabajo1, L=Local, ST=Dev, C=MX" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"

echo "Keystore de desarrollo creado en $OUT"
