### Fixed: finding import accepts files up to its 110 MiB limit and writes in batches

- `POST /api/v1/findings/import` now applies its own 110 MiB body limit. The
  global 10 MiB request limit ran first, so every file above 10 MiB was refused
  with a misleading "larger than 110 MiB" error.
- An import no longer makes three database round trips per finding. The
  priority audit entries are written in one statement per 1,000 findings, SLA
  policies are loaded once per batch instead of once per finding, and the
  version-2 identity re-key runs only for findings that still hold a version-1
  key. A 17.7k-finding nuclei file went from about 213k to about 160k SQL
  statements and imports about twice as fast on the same host.
- A rescan no longer rewrites every finding's source interop data when it is
  unchanged. On a 17.7k-finding rescan, that update went from 9.3 s writing
  17,721 rows to 0.28 s writing none.
- The fingerprint existence check takes the keys as one array parameter, so a
  report above 65,535 findings no longer exceeds PostgreSQL's bind-parameter
  limit.
