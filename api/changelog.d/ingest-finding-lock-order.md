### Fixed: concurrent uploads no longer deadlock on findings rows

- Every batched write of findings rows now locks its rows in one order (fingerprint, byte order). The upsert of new findings locked by fingerprint while enrichment, the sighting update and the finding-priority stamp locked by id, and the interop, scanner output, snippet, branch backfill, auto-reopen and bulk status writes locked in report or plan order. Concurrent uploads of the same findings, and an upload next to a priority pass or a bulk status change, deadlocked (`40P01`).
- The best-effort writers (interop data, scanner output, snippets, branch backfill, priority stamp) dropped their rows on a deadlock with only a warning. They now queue, and a conflict that still happens runs the statement again.
- A failed write of branch occurrences is now reported in the upload's errors, and that scan's occurrence sweep is skipped, so the findings it saw are no longer marked as gone from the branch.
