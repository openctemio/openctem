### Changed: the edition fence checks neutral extension mount points and keeps its word list out of the repository

- Web extension mount points are `web/src/extensions/` and `(extensions)` route groups; the old Go overlay directory `api/ee/` and its build-tag rules are gone (a custom build is its own Go module that calls `api/pkg/server.Main()`).
- New rule: `api/go.mod` has no `replace` directive, so the core always builds from public sources and works as a dependency.
- The restricted-word list is no longer committed: CI reads it from the `FENCE_RESTRICTED_WORDS` secret, a local clone from `.git/info/restricted-words`; without a list the rule is skipped and the script says so.
