### Changed: pull request CI re-runs only what a push changed, and a verified release PR skips the heavy suites

- A push to a pull request is measured against the PR's last commit whose required checks all passed, so areas that did not change since then report success as "unchanged since" that commit. The merge queue and pushes to develop and main still run the full tier.
- A release pull request (release/vX.Y.Z into main) whose content is a develop commit with every required check green plus the version bump (or the last tag plus cherry-picks of green develop commits) skips the heavy suites; anything else runs the full tier. The code-scanning gate of a release PR compares with develop.
- New high or critical code-scanning alerts and fixable image advisories on develop open one GitHub issue labelled security, and the Release Train plan runs a release preflight (`.github/scripts/release-preflight.sh`) that fails on blockers.
