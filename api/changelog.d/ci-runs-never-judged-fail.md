### Fixed: a CI run whose gate job never ran no longer stays "Running" for ever

- A sweeper concludes a CI run that is still running after its 6-hour pipeline window with the verdict `fail` and the reason `not_judged` (the run view shows "Never judged (the gate job did not run)"). Before, a cancelled pipeline or a skipped gate job left no verdict, so nothing blocked the merge. Findings the run uploaded are kept; a run judged in the meantime keeps its verdict.
