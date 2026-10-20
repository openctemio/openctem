### Security: refresh tokens rotate atomically; emailed tokens carry no padding

- A refresh token is now spent with one conditional update (`used_at IS NULL AND revoked_at IS NULL`). Before, two concurrent refreshes of one token both succeeded, forking the session's token family without tripping reuse detection. The loser is now treated as a reuse and ends the session. The first-team and invitation paths also refuse when the old token cannot be recorded as spent.
- Password reset, set-password and email verification tokens are now unpadded base64url, so mail clients that drop a trailing `=` from a link no longer break it. Tokens already issued (padded) are still accepted, with or without the `=`, for one release. Links escape the token.
