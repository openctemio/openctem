### Security: external OIDC provider tokens use the shared verifier

- With `AUTH_PROVIDER=oidc` or `hybrid`, access tokens from the external provider (Keycloak) are verified by the same core as SSO and CI tokens (`pkg/oidc`). The provider's own JWKS fetcher, key parser and cache are removed.
- New for these tokens: an unknown `kid` refetches the realm keys at most once per 30 seconds (it fetched on every request before), RSA keys under 2048 bits or with an exponent over 31 bits are ignored, tokens over 32 KiB are refused, `iat` and `nbf` in the future are refused, and 30 seconds of clock skew are tolerated.
- `KEYCLOAK_BASE_URL` and `KEYCLOAK_REALM` must give an issuer: the validator no longer starts without one.
