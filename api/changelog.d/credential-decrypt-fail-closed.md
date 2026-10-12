### Security: an undecryptable stored credential is never used as is

- Integration credentials (SCM, notification webhooks, Telegram, SMTP,
  Splunk), Jira and GitHub ticketing credentials and the Jira/GitHub inbound
  webhook secret fell back to the stored value when it did not decrypt under
  `APP_ENCRYPTION_KEY`. After a key mismatch that sent ciphertext upstream, and
  a legacy plaintext row was used unencrypted (RFC-049 F-8). They now fail
  closed: the integration reports "stored credentials cannot be decrypted with
  the configured key" (HTTP 424 on the integration endpoints), ticketing skips
  the integration, and an undecryptable webhook secret verifies nothing.
- `APP_ALLOW_PLAINTEXT_CREDENTIALS` (development without a key) is unchanged.
- **Upgrade note:** run `cmd/encrypt-credentials` before upgrading if any
  integration still holds a plaintext credential (it lists them with
  `-dry-run`); re-enter or re-key any credential the current key does not open.
