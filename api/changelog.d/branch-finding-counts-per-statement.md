### Fixed: large uploads to a repository branch are no longer quadratic

- The open-finding counters of a repository branch were recounted over the whole branch five times for every inserted finding. A 5,000-finding report spent most of its time in that recount, and it held the branch row locked across the upload, which serialised every upload of the repository. Migration `003345_branch_finding_counts_per_statement` replaces the per-row trigger with statement triggers that recount each touched branch once per statement. The counts stay exact, and no data is rewritten.
