### Added: decide the review queue a rule at a time (web)

- Discovery › Attack surface › Review shows suggested rules (a wildcard per
  label level, an IP /24 or /48) with how many pending names each covers,
  which stay out and why, and the evidence (verified domain, discovering
  root, network). Shared or CDN addresses are never grouped.
- "Accept as rule" and "Reject as rule" open a preview of exactly what
  changes (names confirmed or marked not ours, names that stay out, the
  approvals the new entry or exclusion needs, step-up) and need a reason;
  the rule is created through the normal scope paths (RFC-054 §6.7).
- The queue filters by the reason a name was queued and shows what covers
  each name; a name nothing covers offers "Add to scope", since confirming
  records ownership but does not let scans reach it.
- The shared "Review changes" preview (`ScopeChangePreview`) is the one diff
  view for scope changes.
