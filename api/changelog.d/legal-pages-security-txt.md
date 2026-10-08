### Added: legal page templates and security.txt

- `LEGAL_PAGES_ENABLED=true` serves built-in templates for the Terms of Service (`/terms`), Acceptable Use Policy (`/acceptable-use`), Privacy Policy (`/privacy`), Data Processing Addendum (`/dpa`) and subprocessor list (`/subprocessors`). Contacts default to info@openctem.io, security@openctem.io, https://openctem.io and https://docs.openctem.io (each configurable with `LEGAL_*`); the company legal name, address, governing law and effective date show as marked placeholders until set. Off by default (404).
- `LEGAL_TERMS_URL` / `LEGAL_PRIVACY_URL` link documents hosted elsewhere and are read at runtime; the sign-in and register notices link whichever is configured.
- `/.well-known/security.txt` (RFC 9116) is served with security@openctem.io by default and a rolling one-year `Expires`; `SECURITY_CONTACT` (email or https URL) replaces the contact, `SECURITY_POLICY_URL` adds `Policy`, `SECURITY_TXT_ENABLED=false` turns it off.
