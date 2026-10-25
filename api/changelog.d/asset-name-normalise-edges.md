### Security: database asset names never keep part of a password

- A database connection string whose password contains `@` (`postgres://admin:S3cr@t!@db.example.com/app`) kept the end of the password in the asset name, visible to every reader and in exports. Credentials now end at the last `@`, after the query and fragment are cut, so an `@` in a query parameter (`?user=svc@corp.example`) no longer merges two databases into one asset named after the parameter.

### Fixed: one asset name for repository, IPv6 host and URL spellings

- `github.com/org/repo.git/` and `ssh://git@host:2222/org/repo.git` normalise to `host/org/repo` in one pass, like the other spellings.
- A bracketed IPv6 host (`[2001:DB8::1]:443`) normalises to `2001:db8::1`.
- A URL with the DNS root dot (`https://example.com./`) or a non-canonical IPv6 host names the same origin as its canonical spelling.
- Existing asset names are not rewritten; a duplicate created under an old spelling shows in the duplicate review.
