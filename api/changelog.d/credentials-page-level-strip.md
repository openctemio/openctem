### Fixed: credential leak counts were wrong past 100 credentials

- The cards and status counts on the Credentials page are counted by the server
  for every credential you can see, instead of from the first 100 rows. They do
  not change with the filters.
- The page loads only the view shown: the list, or the identities.
