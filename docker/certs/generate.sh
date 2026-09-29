#!/usr/bin/env sh
# Generates a throwaway self-signed cert for the legacy-tls-target container.
# Not committed to git (see .gitignore) — regenerate locally before `docker compose up`.
set -eu
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:1024 -nodes \
  -keyout self-signed.key -out self-signed.pem \
  -days 3 -subj "/CN=legacy-tls-target"
echo "Generated docker/certs/self-signed.{pem,key} (intentionally weak 1024-bit RSA)"
