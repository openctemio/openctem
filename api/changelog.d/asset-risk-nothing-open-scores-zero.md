### Behaviour change: an asset without an open finding scores 0 in every risk model

- The weighted risk models (`multiply`, `amplify_headroom`, used by the legacy and industry presets and by custom settings) no longer score an asset that has no open, non-informational finding. Exposure, criticality and data context scale the risk of findings; on their own they are not risk. Such an asset now reads "No open risk", as in the default likelihood-impact model. With open findings the weighted formula is unchanged.
- `risk_score_pending` (the clock next to a score) is true only when a real input change is queued. The daily and start-up reconcile no longer shows every asset as pending for ten minutes.
- The asset page labels `risk_scored_at` "Score last changed": it moves only when the score changes.
