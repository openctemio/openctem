### Fixed: Google sign-in for an address that already has an account answers 409, not 500

- `POST /api/v1/auth/oauth/{provider}/callback` answered `500 INTERNAL_ERROR` when the provider's verified address belonged to an account that signs in another way (a password account, or an account of another provider). It now answers `409 OAUTH_ACCOUNT_EXISTS`; a provider that returns no address answers `400 OAUTH_NO_EMAIL`. Nothing is written in either case.
- The sign-in page keeps a notice on screen: an account with this email already exists, sign in with your password, then link the provider in Account > Security, with a link to reset the password.
