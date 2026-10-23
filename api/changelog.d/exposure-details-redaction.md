### Security: tool-reported secrets in exposure details are masked on the server

- Exposure reads (list, detail, credential list) now replace the value of every details key that looks like a secret (`password`, `api_key`, `token`, `access_token`, `refresh_token`, `private_key`, `secret`, `secret_*`, `client_secret`, `credential`, and keys ending in `_password`, `_token`, `_secret`) with `********`, recursively through nested objects and arrays. `secret_masked` and `secret_fingerprint` stay readable.
- The exposure detail view no longer has a "Reveal secrets" toggle, because the browser no longer receives the value. A leaked credential is still revealed through the audited reveal endpoint.
- Detail copy buttons now have an accessible name.
