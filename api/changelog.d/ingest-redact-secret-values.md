### Security: a secret scanner's raw match is masked in every stored field, not only the snippet

- A secret finding whose title, description, message, tags, properties or remediation repeated the raw secret was stored with it there. Only the snippet was masked. Ingest and the result quarantine now mask raw secret values in every free-text field before anything is stored, fingerprinted or logged, using `ctis.RedactSecretFinding`. The masked form shows at most the first 4 characters of a secret of 16 or more characters, never more than a quarter, and a shorter secret becomes `REDACTED`.
- A secret finding is one of type `secret`, or one from a secret-scanning tool. Its unmasked snippet or `secret.masked_value` is taken for the raw secret, and so is each secret-looking word of it. Values that are already masked are kept, so findings from well-behaved producers are stored as before and keep their identity.
- A producer that sent the raw secret as `secret.masked_value` now has it masked before the per-tenant secret HMAC is computed. Such a finding gets a new identity on its next sighting, and the old one auto-resolves on a full scan.
- The ctis module is updated to the version with `RedactSecretFinding`. That version also locates Nessus host-level results on their host.
- **Upgrade note:** findings stored before this release are not rewritten. The server cannot tell which part of an old title was the secret. To find secret findings whose title or description may still hold a credential, run a query against your database:

  ```sql
  SELECT id, title FROM findings
  WHERE finding_type = 'secret'
    AND (title ~ '(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-'
         OR description ~ '(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-');
  ```

  Then rotate the credentials it lists.
