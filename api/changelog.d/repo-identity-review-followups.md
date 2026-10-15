### Security: repository identity bound to its code host; renames audited; `repomerge` safe against concurrent writes and policy loss

- Repository import records a repository's code host id only when the repository's address is on the
  integration's own host. A self-hosted code host listing `github.com` or `gitlab.com` addresses imports them
  without an id or address, so it cannot claim the public host's repository of that id. CI already takes the
  host from the verified token issuer.
- A repository asset renamed to its code host's current name (by CI or repository import) writes an
  `asset.renamed` audit event with the old and new name.
- `repomerge` locks the duplicate assets before merging, so a CI run or finding written during the merge is
  moved, never lost. A repository whose duplicates carry several gate policies is refused (the dry run lists
  it); `-resolve` merges it keeping the policy at least as strict as every other, and a repository whose
  policies are stricter on different settings is never merged.
