### Fixed: version matching never closes live findings of a tenant it could not read in full

- One matching pass reads at most 100,000 of a tenant's software matches. A tenant with more had its
  read cut off, and the pass then closed the findings of the matches past the limit as "advisory
  updated" although they were still matched; the next pass reopened them. A truncated read now
  creates and reopens from what it read but closes nothing, logs an error, and counts the tenant in
  `close_skipped` on the controller's log line.
