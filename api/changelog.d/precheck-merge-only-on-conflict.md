### Changed: `make precheck` merges the base into a pushed branch only on a conflict

- A pushed branch that merges cleanly with its base is left as it is (the merge queue tests it on top of the newest develop); a conflict is still merged and resolved locally before the push. A branch not pushed yet is still rebased. 89 of 164 "merge develop" commits on 2026-10-23..25 had no conflict and each re-ran the whole CI.
- The web checks run only when a file they read changed (`web/src`, `web/e2e`, `web/scripts`, package and config files), so a change to, say, `web/e2e/ci/docker-bake.hcl` no longer needs `node_modules`.
