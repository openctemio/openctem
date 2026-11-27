### Security: the web console encodes request parameters, quotes completed search values and forwards fewer WebSocket headers

- An integration id taken from the address is encoded as a single path segment in the integration, ticket policy, Jira metadata and repository requests, and the notification history page uses it only when it is a UUID.
- A value completed in the search box is quoted unless it is a plain word, so operator characters, parentheses, commas and reserved words such as `or` cannot change the query.
- The WebSocket forwarder passes only the headers the API needs (cookie, origin, user agent, language and the upgrade headers) and drops `Forwarded`, `True-Client-IP`, `X-Client-IP` and the rest.
- The API proxy answers a failed connection to the API with a fixed message; the detail stays in the server log.
- Docs: web/docs/security-architecture.md
