# Session refresh: rotation, reuse detection and the rotation grace

A signed-in browser holds a short-lived access token (`AUTH_ACCESS_TOKEN_DURATION`,
15 minutes) and a refresh token (`AUTH_REFRESH_TOKEN_DURATION`, 7 days) inside a
session (`AUTH_SESSION_DURATION`, 30 days). `POST /api/v1/auth/refresh` trades the
refresh token for a new tenant-scoped access token and a new refresh token.

## Rotation and reuse detection

Every refresh spends the presented token and issues its successor in the same
token family (`refresh_tokens.family`). The spend is one conditional update in a
transaction that also inserts the successor (`RefreshTokenRepository.RotateIfUnused`):
of several concurrent rotations of one token exactly one wins.

A token presented again after it was rotated means a second copy exists. Outside
the grace below, the session ends: the family, every refresh token of the session
and (through the revocation store) its access tokens are revoked, and
`auth.session_revoked` is audited with `reason = refresh_token_reuse`, severity high.

## Rotation grace

The web console makes many requests at once. When the access token expires, each
of them can reach a refresh with the same refresh token, and requests the browser
sent before the first refresh answered still carry the old cookie after it. Without
a grace, the first one rotates the token and the rest look like theft, so the user
is signed out.

For `AUTH_REFRESH_REUSE_GRACE` (default 30 s, at most 2 min, 0 turns it off) after
a rotation, presenting the replaced token again returns the **same successor** the
rotation issued, plus a fresh access token for the requested organization. No new
token is minted, so the family stays one chain. All of these must hold, otherwise
the request is a reuse and ends the session:

- the replaced token is the immediately previous one: its successor is still
  unused, not revoked and not expired (once the successor rotates, the grace is gone);
- the successor belongs to the same user, session and family;
- the rotation happened at most the grace ago and the token was not revoked since
  (signing out revokes every token of the session, used ones included);
- the same client presents it: a hash of the user agent recorded at rotation
  (`refresh_tokens.rotated_fingerprint`) matches, compared in constant time.

Every refusal the refresh applies (suspended account or organization, membership,
SSO, two-factor, email verification and the other organization policies) runs before
the grace hands anything out. A grace request for an organization the user is not a
member of is refused like any other and does not end the session.

### No secret at rest

The successor is not stored. It is derived: its `jti` is an HMAC of the replaced
token's id under the signing secret, and its issue and expiry times are the
successor row's `created_at` and `expires_at` (whole seconds). HS256 signing is
deterministic, so a grace request rebuilds the identical token string and checks it
against the stored hash (constant time) before returning it. The rotation record on
the replaced row is only `successor_id` and `rotated_fingerprint`; rotated rows are
deleted an hour after use (`DeleteExpired`).

### Threat model

- **Stolen refresh token used after the real client refreshed.** Outside the grace,
  or from another user agent, it ends the session as before. Inside the grace and
  with the same user agent, the thief receives the same successor as the real
  client; both now hold one chain, and the next rotation by either makes the other's
  copy a reuse, which ends the session. The window is bounded (2 min hard cap).
- **Forked family.** Impossible: the grace never mints, and the rotation is a single
  transactional winner.
- **Tenant isolation.** Refresh tokens are global to the user; the access token is
  scoped to the requested organization after the membership check, on the grace path
  too.
- **Logs.** Token values are never logged; the grace path logs the session id only.

## Web console

The Next.js server refreshes through one single-flight function
(`web/src/lib/server-refresh.ts`): concurrent and recent (20 s) calls with the same
refresh token share one API call and its result, keyed by a SHA-256 of the token.
In the browser, refreshes share one in-tab promise and a cross-tab Web Lock, and a
refresh another tab finished moments ago is reused instead of repeated. When a
session ends, the sign-in page says why (signed out elsewhere or for safety,
expired, or ended by an administrator).
