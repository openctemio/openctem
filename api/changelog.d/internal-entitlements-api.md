### Added: internal entitlements API for a hosted service's control plane (off by default)

- A separate listener (`INTERNAL_API_ADDR`, empty by default) lets a hosted service's control plane set per-organization limits and module denies, the self-service default limits, the idle policy, provision organizations, and read aggregate usage counts. See `docs/architecture/limits.md`, "Internal entitlements API".
- Trust: mTLS (TLS 1.3, client certificate from `INTERNAL_API_CLIENT_CA` required) plus a short-lived (at most 5 minutes), single-use, Ed25519-signed token per request with scopes `limits:write`, `orgs:provision` or `usage:read`. Every write is audited as actor `control-plane`. No endpoint returns organization content.
- Self-hosted installs need nothing: with the listener off, nothing changes and limits written by a control plane are ignored.
- **Upgrade note:** only for a hosted service: set every `INTERNAL_API_` variable (the API refuses to start when the address is set and a file is missing).
