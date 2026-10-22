### Added: Verification panel on the finding drawer and page

- A Verification panel shows how the finding can be verified (from the server's verification plan): its risk tier and what resolving needs, each method (retest, covered scan, reachability check, rotation proof, evidence review) with why an unavailable one cannot be used, and the proof recorded so far.
- The verification checklist can now be filled in from the console (with a secret variant for rotation proof). Completing it records who completed it, so another person can resolve a critical finding; the completer is told so.
- The status menu shows why a move is blocked under the move itself, with a lock icon, instead of only on hover.
- "Validate now" is renamed "Check reachability", needs `findings:verify` and is offered only where the check can run (an active network asset, not a secret). The panel hides when there is nothing to show.
- Dates in finding properties follow the user's language.
