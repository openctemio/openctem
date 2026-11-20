### Changed: security overview and scope policy use the settings page frame (redesign branch)

- Security overview: the score, the counts and when it was checked, then one section per group with the checks
  that need a look (each with a Review link that names the check); the passed checks are folded at the end and
  shown on demand. Loading and a failed load look like every other settings page.
- Scope policy: the values in effect, then the policy with the rarely changed options (unclassified assets,
  automatic coverage, info checks, the review gate, proof for CI scopes) folded under Advanced, and one save bar
  instead of a Save button. The owner-only intrusive (T2) limit shows its two values and changes in a dialog that
  asks for the reason. A reader without scope:approve sees the view-only notice.
- Same reads, writes, gates, confirmations and step-up as before. No API change.
- Docs: none (layout of two settings pages; no user guide describes their layout)
