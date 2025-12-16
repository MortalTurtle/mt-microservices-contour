disable_mlock = true

storage "file" {
  path    = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"
  tls_disable = false
  tls_disable_client_certs = true
}

api_addr = "https://certvault.mt.ru:8200"
