### Fixed: the web console refreshes a session once, and says why a session ended

- The web server refreshes through one shared single-flight function: concurrent and
  recent (20s) requests that carry the same refresh token share one refresh and its
  result, so a page load after the access token expired no longer presents a rotated
  token again. A refused refresh (401) is not retried with the same token.
- Browser tabs share one refresh: a tab that waited while another refreshed reuses
  that refresh, and every tab picks up the new access token.
- When a session ends, the sign-in page says why: used from two places, expired, or
  signed out elsewhere / ended by an administrator.
