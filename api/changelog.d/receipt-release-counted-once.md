### Fixed: a quarantined report that is released is counted as received once

- The results quarantine counted a held report's findings as received; the release counted them again, so the intake totals, the funnel and the receipt list showed them twice. The release now moves them off the quarantined outcome and received, and the hold and the release share one receipt. Older receipts keep their earlier figures.
- The intake card's noise bar no longer subtracts suppressed findings from New a second time: the receipt counts suppressed apart from created, so New, Merged, Suppressed and Not stored sum to Received, and suppressed is its own segment.
