##!/bin/sh
set -e

apk add --no-cache jq

mkdir -p /vault/data /vault/logs
chmod 700 /vault/data /vault/logs

/vault/generate_init_certs.sh

vault server -config=/vault/config.hcl &
VAULT_PID=$!
sleep 5

export VAULT_CACERT=/vault/certs/ca.crt
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true

if vault operator init \
    -key-shares=1 \
    -key-threshold=1 \
    -format=json > /vault/data/init.json 2>/dev/null; then

    echo "Initializing Vault..."
    export VAULT_TOKEN=$(jq -r '.root_token' /vault/data/init.json)
    UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' /vault/data/init.json)
    echo "$UNSEAL_KEY" > /vault/data/unseal.key
    chmod 600 /vault/data/unseal.key
    echo "Unsealing Vault..."
    vault operator unseal "$UNSEAL_KEY"
    echo "Setting up PKI..."
    if [ -f /vault/setup_pki.sh ]; then
        /vault/setup_pki.sh
    fi
    echo "Setting up authentication..."
    if [ -f /vault/setup_auth.sh ]; then
        /vault/setup_auth.sh
    fi
elif [ -f /vault/data/init.json ]; then
    echo "Vault is sealed, unsealing..."
    if [ -f /vault/data/unseal.key ]; then
        UNSEAL_KEY=$(cat /vault/data/unseal.key)
        vault operator unseal "$UNSEAL_KEY"
        echo "Vault unsealed successfully"
    else
        exit 1
    fi
else
    echo "Vault is already initialized and unsealed"
fi

echo "Final Vault status:"
vault status -format=json | jq '{
    initialized: .initialized,
    sealed: .sealed,
    standby: .standby,
    performance_standby: .performance_standby,
    version: .version
}'

unset VAULT_TOKEN

echo "Vault is running with PID: $VAULT_PID"
