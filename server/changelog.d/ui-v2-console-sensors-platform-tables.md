### Changed: the console Platform sensors fleet and the Platform scanning job and exception tables follow the shared table pattern (redesign branch)

- Console > Platform sensors, Fleet: column kinds and widths, rows on one line (the sensor's name, then its region;
  its tools as one line of text), the sensor kept in view while the table scrolls sideways, Version and Tools
  stepping aside on a narrow table. Pause or Resume and Retire moved from buttons in the row into the row's menu
  ("Actions for the sensor {name}"); they open the same confirmations (reason, code, the typed name for Retire).
- Console > Platform scanning, Queue: the Jobs table gets the same treatment, its status filter is the table's own
  select, and "Targets and logs" is in the row's menu (the same reason dialog, still only with the jobs permission).
  Blocked names: the Exceptions table gets column kinds and widths, one-line rows, and Extend and Revoke in the
  row's menu (the same dialogs).
- A failed read shows in the table with Retry; each table has a name and its own empty state.
- Nothing moves on first load: on Platform sensors the note on shared scanning in this release sits below the fleet
  table (it appears once the setting is read and pushed the table down by 64 px); on Platform scanning one
  placeholder stands until the shared sensors setting is read (the tabs no longer flash before the closed layout,
  so the two queue reads they made are gone), and the blocked names come once the domain-proof card above is read
  (the Exceptions table moved 449 px).
- No API change: the same reads, page size and dialogs.
- Docs: none (layout of existing console tables; what they read and who may act are unchanged)
