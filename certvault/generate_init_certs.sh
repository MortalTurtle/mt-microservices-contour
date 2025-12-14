#!/bin/sh
set -e

mkdir -p /vault/certs
apk add --no-cache openssl curl ca-certificates >/dev/null 2>&1

if [ ! -f /vault/certs/ca.key ]; then
    echo "Generating Root CA..."
    openssl genrsa -out /vault/certs/ca.key 4096
    openssl req -x509 -new -nodes -key /vault/certs/ca.key \
        -days 3650 -out /vault/certs/ca.crt \
        -subj "/C=RU/CN=mt.ru Internal CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    mkdir -p /usr/local/share/ca-certificates
    cp /vault/certs/ca.crt /usr/local/share/ca-certificates/mt-ca.crt
    update-ca-certificates
fi

if [ ! -f /vault/certs/vault.key ]; then
    echo "Generating Vault server certificate..."
    openssl genrsa -out /vault/certs/vault.key 2048
    openssl req -new -key /vault/certs/vault.key \
        -out /vault/certs/vault.csr \
        -subj "/C=RU/CN=certvault.mt.ru" \
        -addext "subjectAltName=DNS:certvault.mt.ru,IP:192.168.1.100,IP:127.0.0.1"
    openssl x509 -req -in /vault/certs/vault.csr \
        -CA /vault/certs/ca.crt -CAkey /vault/certs/ca.key -CAcreateserial \
        -out /vault/certs/vault.crt -days 365 \
        -extfile <(printf "subjectAltName=DNS:certvault.mt.ru,IP:192.168.1.100")
fi

openssl verify -CAfile /vault/certs/ca.crt /vault/certs/vault.crt && echo "✓ Chain valid"
