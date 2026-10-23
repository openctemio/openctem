### Fixed: load errors explain rate limits and lost connections, and fit on a phone

- When a page section fails to load because of the per-user request limit, it now says "Too many requests in a short time. Wait a few seconds, then retry." (English and Vietnamese) instead of the server's English "Rate limit exceeded"; a lost connection gets its own message too. Other errors keep the server's message.
- On a phone the request id is no longer printed inside the error box, where it ran past the right edge; the "Copy request ID" button still copies it. Wider screens show it as before.
