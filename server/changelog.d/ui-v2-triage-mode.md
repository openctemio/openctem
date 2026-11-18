### Changed: Triage mode lays out the finding and its decision as its own page (redesign branch)

- The page header holds the title, Undo last (with how many decisions can be undone), All keys and Exit;
  Confirm is the page's only filled button. A status line under it shows the queue, the position, this
  session's counts at every width and the progress.
- The queue, the finding and the decision panel are cards side by side on a wide screen; the finding and its
  decision side by side on a narrower one, the queue under them; on a phone the finding, then the
  decision panel, then the queue, with Confirm and this session's counts in a bar fixed to the bottom of the
  screen, always reachable without scrolling. Full page and Evidence are on the finding; Previous and Next close the
  decision panel.
- Every decision, refusal and undo is also said in one status region for screen readers.
- An empty queue shows no empty queue list; a queue that cannot be read shows its error and Retry only.
  Decision buttons stay disabled until a finding is on screen.
- Every key, permission check, lifecycle check, conditional write and dialog is unchanged.
- Docs: none (no guide describes this layout).
