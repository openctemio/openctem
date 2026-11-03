### Security: golang.org/x/crypto updated for GO-2026-5932

- The OpenPGP armor reader in golang.org/x/crypto (GO-2026-5932) is fixed in a post-v0.58.0 commit, so the module is pinned to that commit until the next tagged release. The release-feed test helper and the HTTP body limiter reach the affected reader through the standard library, so the dependency scan blocked every pull request.
