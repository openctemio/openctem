### Security: a failed default-branch CI run can no longer become its own gate baseline

- A default-branch run was compared with what earlier runs had seen, so running a failed run again (or pushing
  again) turned every finding into "already on the default branch" and passed the gate. A default-branch run is
  now judged against the repository's **gate baseline** only; without one, every finding counts as new.
- New: `GET/POST/DELETE /api/v1/ci/repositories/{id}/gate-baseline`. Recording a baseline (the findings open on the
  default branch now) needs `scans:ci:policy` and a recent sign-in, is audited at high severity and announced to
  administrators. Once a repository has a baseline, a pull request run treats a finding as pre-existing only if it
  is also in the baseline. Migration `ci_gate_baselines`.
- **Upgrade note:** repositories with existing findings fail default-branch runs until an administrator records a
  baseline for them.
