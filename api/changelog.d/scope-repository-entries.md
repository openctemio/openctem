### Added: Repository scope entries judge repository assets

- A repository asset now gets a scope verdict (in scope through the entry that covers it, or out of scope) instead of "Scope entries do not apply to this kind of asset".
- Repository entries have one canonical form (lower case, no scheme or `.git`): `host/namespace/repo`, `host/namespace/*` (every repository below the namespace, subgroups included) or `host/*` (a whole self-hosted host). Matching is per path segment: `gitlab.com/acme/*` never covers `gitlab.com/acme-evil/app`. Repository exclusions use the same matcher.
- Security: on a code host many organizations share, only repository entries judge repositories: a domain entry such as `github.com` claims nobody's repositories. On a self-hosted host, an entry for the host covers its repositories.
- Security: a whole-host entry on a code host shared by many organizations (github.com, gitlab.com, bitbucket.org and others, `pkg/domain/scope/public_code_hosts.txt`) is refused with `SHARED_CODE_HOST`; name a namespace there. Operators add hosts with `SCOPE_PUBLIC_CODE_HOSTS_EXTRA`. The deny list applies to code hosts.
- "Add to scope" on a repository asset proposes a repository entry.
