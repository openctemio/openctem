### Security: The platform test e-mail is rate limited per administrator
- `POST /api/v1/admin/settings/email/test` allows 5 test messages per minute per administrator and answers `429` beyond that, so the route cannot be used to send a stream of mail through the stored SMTP server. Other limits are unchanged.
