### Security: key rotation re-encrypts the CAPTCHA secret and the alert webhook

- `cmd/rekey` now re-encrypts the console's CAPTCHA secret and the alert webhook address and signing secret. Before, rotating `APP_ENCRYPTION_KEY` left them sealed under the old key: sign-in steps that need CAPTCHA were refused and alerts stopped. A test fails when a console setting adds an encrypted field the tool does not cover.
