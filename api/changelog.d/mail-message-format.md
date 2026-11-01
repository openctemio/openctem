### Fixed: e-mail has Date and Message-ID headers, encoded non-ASCII subjects and a plain-text part

- Mail from the platform now carries `Date`, a `Message-ID` on the sender's domain and `Auto-Submitted: auto-generated`.
  Subjects and sender names with non-ASCII text (for example Vietnamese organization names) are RFC 2047 encoded.
  HTML mail is sent as `multipart/alternative` with a generated plain-text part, quoted-printable encoded and wrapped
  at 76 characters. CR and LF in any header value are still removed, so a value cannot inject a header.
- The notification e-mail channel now sends through the same `pkg/email` sender as account mail, so there is one
  SMTP stack. TLS rules, the port and managed-service rules, and the choice between the platform relay and an
  organization relay are unchanged.
