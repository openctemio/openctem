### Changed: the console says when a risk score is not computed yet, and why a score is what it is

- An asset that was never scored shows "Not yet scored" and a first score in
  the queue "Calculating…", instead of a score of 0; a queued rescore keeps
  the score with a spinner. The asset's Risk card shows when the score was
  last computed.
- "Why this score?" on the asset's Risk card lists the model's factors
  (findings per severity with exploitable counts, exposure, effective
  criticality, compensating controls) and the open findings that drive the
  score, each linked to the finding.
- Risk level labels follow the organization's bands everywhere and are
  translated: 0 reads "No open risk" and a score below the low band "Minimal"
  (it read "Info").
