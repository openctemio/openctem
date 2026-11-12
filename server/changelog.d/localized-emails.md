### Added: transactional e-mails in English and Vietnamese

- Verification, password reset and changed, welcome, invitation, account setup, member suspended and reactivated, security notices and the domain-managed notice are written in one language per recipient: the account's own language, else the default language of the organization the e-mail is sent for, else English. Any other language falls back to English.
- The wording lives in per-language catalogs (`server/pkg/email/locales/en.json`, `vi.json`); the HTML layout is shared. A failed language lookup falls back to English and never blocks the e-mail.
- Subjects are no longer HTML-escaped (an apostrophe in an organization name no longer shows as `&#39;`); line breaks are still stripped and the header encoded.
- Texts other packages pass in whole (SAML certificate expiry, e-mail relay stopped, support access, ownership transfer, and the summary line of an SSO change) stay as supplied.
