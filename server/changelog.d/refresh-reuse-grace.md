### Fixed: parallel requests no longer sign people out

- Several requests refreshing the session at the same moment (a page load after the
  access token expired, several tabs) presented the same refresh token; the first
  rotated it and the others were treated as a stolen token, ending the session. For a
  short grace after a rotation (`AUTH_REFRESH_REUSE_GRACE`, default 30s, max 2m, 0
  off), the same client presenting the token it just rotated receives the successor
  already issued. Any other reuse still ends the session and is audited.
- Migration `20261031184414_refresh_token_rotation_successor` adds two nullable
  columns to `refresh_tokens` (catalog-only change).
