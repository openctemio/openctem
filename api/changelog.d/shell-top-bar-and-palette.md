### Changed: 48 px top bar and a command palette that searches

- The top bar is 48 px high, with the search (the command palette, Ctrl+K or Cmd+K) in its middle, labelled "Search or go to". People who may approve findings get an approvals button with the number of requests waiting for their decision; it opens My Work on that queue.
- The palette searches findings, assets and remediation tasks from two characters on, through each type's own list API, so results follow the caller's tenant and data scope. A type the caller may not read is not searched. A CVE id opens its findings. It also lists the findings quick views with counts and the saved views.
- Typing `>` lists commands only. The commands open a form (New scan, Import results, Create remediation task), each offered only with its permission. The palette never changes data: every write stays on its page, with that page's confirmation and step-up. Pages open the form from `?new=scan|import|task` only when the caller has the page's own permission.
- Palette text is translated (English and Vietnamese).
