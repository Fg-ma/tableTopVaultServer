# Allow the server to validate its own token
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow the server to mint single-use tokens
path "auth/token/create" {
  capabilities = ["update"]
}
