### Fixed: a CI upload no longer deletes another import's package list for the same lock file

- A CI SCA report carries only the vulnerable packages of a lock file and the packages on their paths. Its package snapshot replaced every package stored for that lock file on the repository, so the full list from an SBOM upload or a code-host connector shrank to the CI subset on every run.
- A report now prunes only the packages its own channel listed. A CI list refreshes the packages it names without taking them over, so the next SBOM upload still owns and prunes them; a finding import only adds.
