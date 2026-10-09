### Security: the console's API proxy keeps the API's security headers

- The web console forwards `/api/v1/*` to the API.
- Until now it dropped the API's `Content-Security-Policy` (`default-src 'none'`), `X-Content-Type-Options: nosniff` and `Content-Disposition` headers on every answer that was not a binary file, so a non-JSON answer could render on the console's own origin with no policy. Examples are an HTML report, or a file built from scan data.
- The proxy now forwards those headers on every answer, including streamed files, which also keep their attachment disposition.
