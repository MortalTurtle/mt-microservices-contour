##!/bin/sh

set -e

vault secrets enable -path=pki_internal pki
vault secrets tune -max-lease-ttl=87600h pki_internal

vault write pki_internal/config/ca \
    pem_bundle="$(cat /vault/certs/ca.key /vault/certs/ca.crt)"

vault write pki_internal/roles/certservice-role \
    allowed_domains="mt.ru" \
    allow_subdomains=true \
    allow_ip_sans=true \
    max_ttl="168h" \
    key_bits=2048 \
    require_cn=false \
    allowed_other_sans="*" \
    generate_lease=true
