### Changed: the Imports list says what each upload and run changed

- Findings > Imports shows one "What changed" column in words ("12 new, 3 resolved, 1 reopened", "No change, 40 still detected", "No findings") instead of six count columns that read 0 on most rows. The counts stay in each receipt's sheet, in the totals under the list and under Display > Columns.
- The status shows only when it needs a look: Failed, Queued, Processing, or Partly stored (some findings could not be stored or the run reported problems). Completed runs carry no chip.
- Runs of one tool that received no findings at all (asset discovery such as subfinder) fold into one row, "15 runs, no findings, 40 assets found". Its sheet lists every run, each opening its own receipt, and links to the asset changes over those runs; nothing is dropped.
- The Source filter and the filter chips from a dashboard link share one toolbar row.
- On a phone the change summary is the card's main line.
- Docs: server/docs/architecture/ingest-receipts.md (web section) updated; the user docs (docs PR #316) have no Imports text or screenshot to change.
