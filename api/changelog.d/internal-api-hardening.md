### Security: internal entitlements API hardening

- The internal API refuses to start without Redis: single-use tokens are remembered across every replica.
- It refuses an every-interface `INTERNAL_API_ADDR` (`:9443`, `0.0.0.0`, `::`) unless `INTERNAL_API_ALLOW_ALL_INTERFACES=true`.
- `POST /internal/v1/organizations` refuses an owner email that already has an account (409 `OWNER_ACCOUNT_EXISTS`) instead of making that person owner: they sign in and create the organization themselves.
