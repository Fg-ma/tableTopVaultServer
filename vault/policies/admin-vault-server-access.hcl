path "secret/data/vaultServer/nginx-internal-token" {
  capabilities = ["read"]
}

path "secret/data/vaultServer/table-top-vault-server.key" {
  capabilities = ["read"]
}

path "secret/data/vaultServer/table-top-vault-server-nginx.key" {
  capabilities = ["read"]
}

path "secret/data/vaultServer/table-top-vault-server.crt" {
  capabilities = ["read"]
}

path "secret/data/vaultServer/table-top-vault-server-nginx.crt" {
  capabilities = ["read"]
}

path "secret/data/vaultServer/table-top-vault-server-dhparam.pem" {
  capabilities = ["read"]
}

path "secret/data/vaultServer/table-top-vault-server-dhparam-nginx.pem" {
  capabilities = ["read"]
}

path "secret/data/tableTop/ca.pem" {
  capabilities = ["read"]
}
