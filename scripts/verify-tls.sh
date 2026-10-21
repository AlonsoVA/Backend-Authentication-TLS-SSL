#!/usr/bin/env bash
set -euo pipefail

BASE_HTTPS="${BASE_HTTPS:-https://localhost:8443}"
BASE_HTTP="${BASE_HTTP:-http://127.0.0.1:8080}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "1. HTTP sin cifrar debe responder 426"
code="$(curl -sS -o "$WORKDIR/http.json" -w "%{http_code}" "$BASE_HTTP/api/public/health")"
echo "   status=$code body=$(cat "$WORKDIR/http.json")"
test "$code" = "426"
grep -q "TLS 1.2" "$WORKDIR/http.json"

echo "2. HTTPS /api/public/health"
curl -skf "$BASE_HTTPS/api/public/health"
echo

echo "3. Recurso protegido sin token -> 401"
code="$(curl -sk -o "$WORKDIR/unauth.json" -w "%{http_code}" "$BASE_HTTPS/api/secure/profile")"
echo "   status=$code body=$(cat "$WORKDIR/unauth.json")"
test "$code" = "401"

echo "4. Login de user y acceso al perfil"
token="$(curl -sk -X POST "$BASE_HTTPS/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"User123!"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["accessToken"])')"
code="$(curl -sk -o "$WORKDIR/profile.json" -w "%{http_code}" \
  -H "Authorization: Bearer $token" \
  "$BASE_HTTPS/api/secure/profile")"
echo "   status=$code body=$(cat "$WORKDIR/profile.json")"
test "$code" = "200"

echo "5. user sobre /api/admin/** -> 403"
code="$(curl -sk -o "$WORKDIR/forbidden.json" -w "%{http_code}" \
  -H "Authorization: Bearer $token" \
  "$BASE_HTTPS/api/admin/reports")"
echo "   status=$code body=$(cat "$WORKDIR/forbidden.json")"
test "$code" = "403"

echo "6. admin sobre /api/admin/** -> 200"
admin="$(curl -sk -X POST "$BASE_HTTPS/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin123!"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["accessToken"])')"
code="$(curl -sk -o "$WORKDIR/admin.json" -w "%{http_code}" \
  -H "Authorization: Bearer $admin" \
  "$BASE_HTTPS/api/admin/reports")"
echo "   status=$code body=$(cat "$WORKDIR/admin.json")"
test "$code" = "200"

echo "7. Handshake TLS 1.2"
curl -skf --tlsv1.2 --tls-max 1.2 "$BASE_HTTPS/api/public/health" >/dev/null

echo "8. Handshake TLS 1.3"
curl -skf --tlsv1.3 --tls-max 1.3 "$BASE_HTTPS/api/public/health" >/dev/null

echo "9. TLS 1.0 debe fallar el handshake"
if curl -sk --tlsv1.0 --tls-max 1.0 --max-time 15 "$BASE_HTTPS/api/public/health" >/dev/null 2>&1; then
  echo "El servidor aceptó TLS 1.0" >&2
  exit 1
fi

echo "Verificación TLS/SSL y autenticación completada."
