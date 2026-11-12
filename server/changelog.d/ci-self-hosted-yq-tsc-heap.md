### Fixed: CI jobs on the self-hosted runners

- `API static checks` installs `yq` when the runner image lacks it again; the installer from the self-hosted runner fix was lost in a later merge, so the job failed with `yq: command not found`.
- `Web checks` gives `tsc` a 4 GB heap; Node's default on a self-hosted runner (about 2 GB) ran out.
- The Scans › Configurations page tests get a 30 s test timeout: every interaction re-renders the 25-row table, and on a busy runner a test with five interactions passed the 5 s default.
