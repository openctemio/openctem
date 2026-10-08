### Changed: every list validates its paging the same way

- The latest-N lists (asset merge log, tag suggestions, EASM rules, a
  finding's retests, sensor activity and manifests) read `limit` with one
  shared parser: a value that is not a positive whole number is refused
  with 400 instead of being ignored, and a value above the list's maximum
  is lowered to it. The pentest campaign, finding and template lists and
  the simulation runs list read `page` and `per_page` with the shared page
  parser. A test now fails on any handler that reads paging parameters
  itself.
