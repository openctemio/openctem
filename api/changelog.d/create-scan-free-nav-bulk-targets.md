### Changed: New and Edit Scan can be moved through freely, with a live summary and bulk targets

- Every step of the New and Edit Scan wizards can be opened at any time, also before the earlier ones are
  complete. Each step shows whether it is complete or how many problems it has; Create (or Save) stays
  disabled until every step is valid and names the first problem as a link to its step. Ctrl/Cmd+Enter
  creates or saves.
- A summary beside every step (a bar above the footer on phones) shows what will run, the intensity in
  plain words and whether the scan needs an approval, how many targets there are, the schedule with its
  next runs, and an estimate of the jobs per run.
- Targets: "Paste or upload a list" reads a pasted list or a `.txt` / `.csv` file in the browser, shows the
  kinds, repeats and every entry that will not be added with the reason (fix or remove one, or all), and
  adds the new ones in one go. Past 20 typed targets they show as a searchable list with the scope answer
  of each. Unicode domains are sent in their ASCII form and `[v6]:port` is accepted; ranges larger than
  65,536 addresses, punycode top-level domains and repository references are refused with the reason
  before create, as the API does.
- Workflow steps in the summary: each step says the tool it runs with, or that it is skipped and why (no tool
  provides the capability yet, no sensor offers it) with the fix, and how many of the steps will run. The
  starter workflows say up front which optional steps are skipped. Tool readiness never blocks Create or Save.
- The New Scan draft is kept per organization and per user in the tab; closing with changes offers
  "Keep as draft". Edit Scan no longer resets the form when the scan is refetched while it is open.
