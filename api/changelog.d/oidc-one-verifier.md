### Security: one token verifier for SSO, Microsoft sign-in, back-channel logout and CI tokens

- Tenant SSO id_tokens, the global "Sign in with Microsoft", OIDC back-channel logout tokens, the platform administrators' identity provider and CI workload tokens are now verified by one core (`pkg/oidc`). The separate SSO verifier and its JWKS cache are removed.
- SSO and Microsoft sign-in gain what the core already enforced elsewhere: the JWKS fetch passes the SSRF URL guard before dialing, an unknown `kid` refetches the keys at most once per 30 seconds (a flood of made-up `kid`s no longer fetches on every request), RSA keys under 2048 bits are ignored, tokens over 32 KiB are refused, and `iat` and `sub` are required. `azp`, when present, must be the client.
- During a provider outage, keys fetched in the last 24 hours keep verifying the `kid`s they hold; a key the provider removed stops working at its next successful fetch.
- Trust stays per flow: SSO identity providers, the platform identity provider and CI trust configurations are configured and checked separately.
