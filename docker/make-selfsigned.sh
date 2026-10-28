#!/usr/bin/env bash
# Creates a self-signed certificate in ./certs for testing. Use your own CA cert in production.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
HOST="${1:-ipam.example.com}"
mkdir -p certs
openssl req -x509 -nodes -newkey rsa:3072 -days 365 -subj "/CN=${HOST}" \
  -addext "subjectAltName=DNS:${HOST}" \
  -keyout certs/privkey.pem -out certs/fullchain.pem
chmod 644 certs/fullchain.pem; chmod 644 certs/privkey.pem   # container user (uid 101) must read it; protect the host directory instead
echo "Wrote certs/fullchain.pem and certs/privkey.pem for ${HOST}"
