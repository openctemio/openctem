### Added: edit the findings filter as text

- The findings filter bar has a Query toggle (Ctrl+/): the whole filter as one line of text in the shared search box, e.g. `severity>=high kev=true -status:accepted last_seen<7d domain=*.example.com`. Filters that chips can show are written back as the usual URL params, so links and bookmarks keep their form; a filter chips cannot show (an OR across fields, a group) is kept as `fq=<text>` and shown as one Advanced chip, never dropped.
- With an `fq` filter the list runs through `POST /findings/search`; the overview numbers are not shown, and stats, export and bulk actions refuse it rather than acting on a wider set.
