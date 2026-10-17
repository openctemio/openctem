### Security: a failed default-branch CI run can no longer become its own gate baseline

- A default-branch run was compared with what earlier runs had seen, so running a failed run again (or pushing
  again) turned every finding into "already on the default branch" and passed the gate. A default-branch run is
  now judged against the repository's **gate baseline** only.
- The first verified default-branch run of a repository records its baseline (the findings open on the default
  branch) and passes on them, once per repository; the verdict and the audit log say so. Secrets still block.
- New: `GET/PUT/DELETE /api/v1/ci/gate-baselines/{id}`. Recording a new baseline by hand needs
  `scans:ci:policy` and a recent sign-in, is audited at high severity and announced to administrators; removing it
  makes every finding count as new again and no run records another. Once a repository has a baseline, a pull
  request into the default branch treats a finding as pre-existing only if it is also in the baseline. Migration
  `ci_gate_baselines`.
- **Upgrade note:** the next verified default-branch run of each repository records its baseline.
