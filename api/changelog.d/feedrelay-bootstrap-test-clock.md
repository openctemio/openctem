### Fixed: feed relay bootstrap alert test no longer depends on the calendar date

- The test fixture published its feed at a fixed 2026-11-01 stamp while the test ran on the wall clock, so the vulnfeed age alert fired once the date passed 2026-11-03.
