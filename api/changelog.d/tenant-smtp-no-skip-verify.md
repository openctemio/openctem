### Security: a tenant can no longer turn off TLS verification for its SMTP relay

- The email notification integration accepted `skip_verify: true`, which sent
  the tenant's SMTP username and password to a relay whose certificate was
  never checked (RFC-049 F-5). Creating or updating an email integration with
  `skip_verify: true` is now refused (400), and the flag is no longer stored.
- Integrations stored with `skip_verify: true` are read without it: delivery
  verifies the relay certificate, and a relay with a self-signed or private-CA
  certificate now fails delivery instead of sending the credentials unverified.
- The operator-level `SMTP_SKIP_VERIFY` for the system relay is unchanged.
- **Upgrade note:** a tenant whose relay uses a self-signed certificate must
  give it a certificate from a CA the API trusts (or the operator adds that CA
  to the API container).
