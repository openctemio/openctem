### Changed: changelog entries are one file per change

- Unreleased entries live in `api/changelog.d/<short-slug>.md`, one file per
  change, instead of the top of `api/CHANGELOG.md`, so pull requests no longer
  conflict on the changelog. The release folds them in with
  `api/scripts/changelog.py release vX.Y.Z`.
- API CI refuses an entry written under Unreleased in `CHANGELOG.md` and any
  merge-conflict marker committed in a tracked text file.
