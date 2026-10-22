### Security: SAML sign-in accepts each assertion once, requires a signed assertion and refuses SHA-1

- Each SAML assertion ID is recorded in Redis until the assertion can no longer be accepted; a second use is refused. If Redis is unreachable the sign-in is refused (fail-closed). Without a Redis client the IDs are kept in process (single replica only).
- The response must hold exactly one assertion, and that assertion must carry its own valid signature even when the whole response is signed. Encrypted assertions and the artifact binding are refused.
- Any SHA-1 signature or digest method is refused. **Upgrade note:** an IdP still signing with RSA-SHA1 must be switched to SHA-256 before upgrading, or its SAML sign-ins fail.

### Added: SAML identity provider certificate expiry alerts

- Owners are alerted in-app and by email 30, 7 and 1 day(s) before the organization's SAML IdP certificate expires, and when it has expired. Saving an expired certificate is refused, and the admin SAML view shows `certificate_not_after`.
- Migration `003286_saml_cert_expiry_notice` adds the nullable `saml_providers.cert_expiry_notice_days`.
- **Upgrade note:** SAML IdPs that encrypt assertions are now refused; configure the IdP to send signed, unencrypted assertions.
