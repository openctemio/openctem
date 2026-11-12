### Fixed: every receipt reconciles on every ingest path

- A finding whose store failed, or whose batch failed the fingerprint check, is counted as failed with its error; before, a failed fingerprint check left the batch on no count, and a failed batch store hid the skipped findings beside it.
- A failed finding is no longer also counted as still detected when a row with its key exists.
- An upload's records the parser skipped (below the minimum severity) and bundle files it did not read count as received as well as skipped, so the upload's receipt reconciles.
- A report held in the results quarantine counts its findings under the new `quarantined` outcome.
- The receipt view shows the findings closed on arrival by a rule, and says how many received findings an older receipt does not explain. "Repeats merged" reads "Repeated in the same scan".
- The dashboard funnel keeps "received → new or reopened"; its tooltip lists where every received finding went (seen again unchanged, repeated in the same scan, closed on arrival, not stored, each other outcome, and what older receipts leave unexplained). The intake API returns `noise.seen_again`, `noise.repeated`, `noise.outcomes`, `noise.unaccounted` and each source's `outcomes`.
