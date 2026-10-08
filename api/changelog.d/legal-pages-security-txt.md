### Added: legal page templates and security.txt

- `LEGAL_PAGES_ENABLED=true` serves built-in Terms of Service and Privacy Policy templates at `/terms` and `/privacy`, filled from `LEGAL_ORGANIZATION_NAME`, `LEGAL_CONTACT_EMAIL`, `LEGAL_ADDRESS`, `LEGAL_JURISDICTION` and `LEGAL_EFFECTIVE_DATE` (unset values show as bracketed placeholders). Off by default (404). `LEGAL_TERMS_URL` / `LEGAL_PRIVACY_URL` link documents hosted elsewhere and are read at runtime; the sign-in and register notices link whichever is configured.
- `SECURITY_CONTACT` (email or https URL) publishes `/.well-known/security.txt` (RFC 9116) with a rolling one-year `Expires`; `SECURITY_POLICY_URL` adds `Policy`. Without a contact it answers 404.
