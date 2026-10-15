### Removed: the older auto-resolve and reopen repository methods

- `FindingRepository.AutoResolveStale`, `AutoResolveStaleByAssets` and
  `AutoReopenByFingerprint` are removed. Nothing called them; they closed
  findings with a weaker rule (no coverage proof) than the coverage
  auto-resolve and reopened with a narrower one than the scan re-detection
  that replaced them.
- The findings state tabs (Open, Fixed, Dispositioned, All), their
  descriptions and the drawer's status, severity and assignee toasts are now
  translated (en and vi).
