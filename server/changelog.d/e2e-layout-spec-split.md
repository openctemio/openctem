### Fixed: the layout check no longer fills one end-to-end shard

- The layout check (spec 75) had grown to about 65 routes and variants in one file, and the shard planner places whole files, so one shard held all of it and ran into its 25 minute timeout. It is now four specs by family: 75a lists, 75b settings, 75c entry and shell, 75d detail pages (the web origin Paths tab), with the checks shared in `web/e2e/helpers/layout-breaks.ts`.
- The shard planner now costs a spec with no recorded duration as the heaviest recorded spec, not the median, so a spec the last green run knows nothing about is never packed with others into one shard.
- Docs: none (test tooling only; the e2e README lists the new specs)
