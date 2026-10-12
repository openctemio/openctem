### Security: a reused refresh token ends the whole session

- A refresh token presented after it was rotated (a stolen copy, or the
  client's own stale copy) now revokes the session, its refresh tokens and,
  through the revocation store, its access tokens at once, and writes a
  high-severity `auth.session_revoked` event (`reason=refresh_token_reuse`).
  Before, only the token family was revoked and the access tokens kept
  working until they expired. The same rule now covers every path that
  accepts a refresh token: refresh, tenant exchange, first-team creation,
  invitation acceptance and the admin console session start.
- The tenant exchange (`POST /auth/token`) records the old token as used
  before it issues new ones and refuses the exchange if that write fails.
  It used to issue first and only log the failure, which could leave the old
  token usable next to the new one.
