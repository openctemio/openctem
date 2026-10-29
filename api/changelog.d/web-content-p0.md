### Added: web content intelligence, first slice

- Origin response header posture (`http_posture` on `http_service` assets): allow-listed flags and enums only, never a header or cookie value. Reports without it are unchanged.
- Endpoints get platform labels at ingest: `ext:backup|config|archive|dbdump|source|log` from the file extension and `auth:login` for a password form.
- The sensitive-path catalog gains a `verify` field; the 20 most critical entries are mapped to signed template ids. New or changed 2xx in-scope catalog endpoints are verified by a budgeted `web_verify` run (100 endpoints per tenant per day, T1 only, excluded paths never requested). A finding is filed only from a template hit.
- New change kinds `web_sensitive_new`, `web_auth_lost` and `web_param_added_sensitive` in the attack surface changes and the weekly digest. A critical new sensitive path and a lost authentication also alert at once, once per alert fingerprint lifetime.
- Migration 003432: `web_endpoint_verifications`, `web_alert_fingerprints`, and `web_verify` as a managed scan owner.
