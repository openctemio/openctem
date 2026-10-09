### Added: authorization letters (RFC-065)

- `POST /api/v1/scope/letters` uploads a letter of authorization (PDF, PNG or JPEG up to 10 MB; title, issuer, reference, `valid_from`, `valid_until` at most 2 years later). The file SHA-256 is recorded. `GET /api/v1/scope/letters`, `GET /api/v1/scope/letters/{id}/file`, `POST /api/v1/scope/letters/{id}/revoke` (scope approvers; audited, administrators notified). Migration 001490.
- A scope entry with `authorization_source: authorization_letter` names a valid letter of the organization (`letter_id`); it goes through the organization approval policy and authorizes only while the letter is valid: expiry and revocation stop scanning at once.
- A letter file cannot be deleted through the attachment routes; the letter is revoked instead.
