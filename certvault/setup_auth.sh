#!/bin/sh
set -e

vault auth enable approle

mkdir -p /vault/data/certservice

cat > /tmp/certservice-policy.hcl << 'EOF'
path "pki_internal/issue/certservice-role" {
  capabilities = ["create", "update"]
}

path "pki_internal/cert/ca" {
  capabilities = ["read"]
}

path "pki_internal/revoke" {
  capabilities = ["update"]
}
EOF

vault policy write certservice /tmp/certservice-policy.hcl

vault write auth/approle/role/certservice \
    token_policies="certservice" \
    token_ttl="24h" \
    token_max_ttl="48h" \
    secret_id_ttl="8760h" \
    secret_id_num_uses=0 \
    token_num_uses=0 \
    bind_secret_id=true

ROLE_ID=$(vault read -field=role_id auth/approle/role/certservice/role-id)
echo "Role ID: $ROLE_ID"
echo "$ROLE_ID" > /vault/data/certservice/role_id

SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/certservice/secret-id)
echo "Secret ID generated"
echo "$SECRET_ID" > /vault/data/certservice/secret_id

LOGIN_RESPONSE=$(vault write -format=json auth/approle/login \
    role_id="$ROLE_ID" \
    secret_id="$SECRET_ID")

APPROLE_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.auth.client_token')

echo "$APPROLE_TOKEN" > /vault/data/certservice/token

chmod 644 /vault/data/certservice/*
