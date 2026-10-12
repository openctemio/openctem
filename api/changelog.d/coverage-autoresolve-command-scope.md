### Security: scan coverage closes findings only on the assets its command covers

- A scan run that reports full coverage (`INGEST_COVERAGE_AUTO_RESOLVE=enforce`) closed the open findings of its tool on every existing asset its report named, including assets the command was never sent to scan. A compromised sensor could close real findings anywhere in its organization by naming their assets in a report. Coverage is now limited to the assets the command targets cover, as repository runs already were. In the default `dry_run` mode the would-be closures shrink the same way.
