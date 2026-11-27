### Fixed: CI/CD refused jobs are grouped, and a CI run's findings are a compact list in a wider sheet

- Connection sheet, Health: identical refused jobs (same repository, ref, event, pipeline file and rule) are one row with how many jobs it holds ("12 jobs") and when the last one came, with one fix per row. The first five rows show and "Show 5 more" adds the next ones, so a pipeline refused on every push no longer fills the sheet with copies. The Pipelines tab's "Recent refused pipelines" and the "see why" sheet use the same grouped list.
- CI run sheet: the findings that block a run, the comment-only ones and the notes are grouped by type (Secret, Known exploited, Severity...) with a count, and each finding is one row: severity, title (its explanation in the tooltip), file:line and Open. Each type shows ten rows, then "Show 10 more".
- The CI run sheet widens with the window (about 42rem, 56rem from 1280 px, 72rem from 1536 px) instead of a fixed 36rem column. Detail drawers of the `xl` and `2xl` widths also grow on wide screens (from 1536 px and 1920 px); form-sized drawers keep their width.
- Docs: none (layout of existing views, no behaviour change)
