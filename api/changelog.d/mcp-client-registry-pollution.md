### Security: unauthenticated MCP authorization requests no longer fill the AI applications list

- `GET /oauth/authorize` fetched a Client ID Metadata Document for any `https` client_id and stored the client, with the name the document chose, before anyone had signed in. Anyone on the internet could therefore fill the platform administrators' AI applications list with entries that looked legitimate. The fetched document now travels with the authorization request and the client is stored only when a signed-in person approves the consent. A client blocked after the request started is refused at approval.
- Migration: metadata-document clients that no one ever approved (no grant, no authorization request in the last day, not blocked) are deleted.
- Console, System, AI applications: applications that name themselves show their host first and the name as "declares itself as"; the usage line is separate items instead of one dotted line.
