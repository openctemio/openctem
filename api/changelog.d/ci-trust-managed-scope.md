### Added: A CI trust adds the repositories it trusts to scope

- Creating a CI trust configuration now adds a linked repository scope entry for each owner (`<host>/<owner>/*`) or repository (`<host>/<owner>/<repo>`) it trusts, in effect at once ("Trust and add to scope", `manage_scope`, on by default). GitHub (github.com and GitHub Enterprise Server) and GitLab (gitlab.com and self-managed) trusts manage scope; other providers name their code host per run and do not.
- An equal entry that already exists is linked, never duplicated, and stays the person's. Entries the trust created (origin `ci_trust`) follow the trust: an edit moves them, disabling or deleting the trust retires them, and two trusts on one namespace share one entry until the last goes.
- The first verified pipeline run under a pattern is recorded as evidence (`scope_entries[].seen_*` on the trust, `managed_by[]` on the scope entry). A legacy-audience run never counts.
- Opt-in governance: the scope setting `ci_scope_requires_proof` (default off) keeps a trust's new entries inactive until a verified run under them.
- Security: an entry a trust manages answers 409 `CI_TRUST_MANAGED` to scope edits of its tier, expiry, reason or discovery, to activate, deactivate and delete; change the trust or add an exclusion. Links are tenant-scoped with composite foreign keys.
- Migration `002140_ci_trust_managed_scope`: `ci_trust_configs.manage_scope` (default true), origin `ci_trust`, table `scope_target_ci_trusts`. Existing trusts get their entries at their next pipeline run, or at once with the backfill command.
