ui            = true
disable_mlock = true

storage "file" {
  path = "/bao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Modo dev-like: auto-unseal con token raíz conocido
# En producción se usaría auto-unseal con KMS o Shamir
api_addr = "http://0.0.0.0:8200"
