# Changelog

## 0.1.0 - 2026-09-10

- `Backend.libcrypto`, performing every algorithm `Jose.Alg` names over OpenSSL, with keys prepared once from a JWK.
- Signing keys read from unencrypted PKCS#8 and PEM, which is where a private key comes from since a JWKS never carries one.
