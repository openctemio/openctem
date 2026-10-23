### Fixed: the people chip no longer calls real members "Former member" in large organizations

- The chip that names who created or approved something looked the user up in the first 100 members only, so in an organization with more members everyone past the first page read "Former member". It now asks for exactly the ids on screen (one batched request per screen) and says "Former member" only when the id is not a member of the organization.
- Added: the members list (`GET /api/v1/tenants/{tenant}/members`, `members:read`) accepts `user_ids`, a comma-separated list of at most 100 user ids. Only members of the listed organization are returned; a malformed id is a 400.
