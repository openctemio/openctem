### Added: the matcher compares package versions under their own ecosystem's rules

- Versions stored under the `semver`, `npm`, `go`, `pep440`, `maven`, `deb`,
  `rpm` and `apk` schemes are now compared the way their ecosystem orders
  them (pre-releases, epochs, build metadata, qualifiers, revisions). Before,
  only `generic` versions were compared, so no package version ever matched a
  vulnerability range.
- A `generic` range (the corpus ranges today) is read under the version's
  scheme; a range of another specific scheme never applies, and a version or
  bound that does not parse gives no match.
- A `deb`, `rpm` or `apk` version matched by an upstream range carries the
  new reason `backport_possible` and −30 confidence, so it stays a potential
  match: distributions often ship a fix without changing the upstream
  version, and per-distribution ranges are not in the corpus yet.
- No migration. Existing versions are evaluated on the next corpus change or
  matcher sweep.
