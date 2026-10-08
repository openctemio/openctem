### Security: probing jobs queued before scope records existed are re-checked at claim too

- Validate, retest and `connector_scan` jobs queued before the dispatch-gate record existed are re-checked at claim with their type's strict defaults (the full gate at t1, no act scope; no zone routing for a connector scan) instead of being handed out unchecked.
- One whose targets cannot be read from its payload is refused with the new failure code `GATE_RECORD_MISSING` (class `scope`, not retried); its validation run, retest or step is settled, and its owner creates it again.
