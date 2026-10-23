### Fixed: the ingest queue no longer grows for ever, and an accepted quarantined report is always applied

- A new hourly job, `ingest-queue-retention`, deletes stored upload parts once nobody will open them (applied, expired 7 days after a failure, or staged by an upload that never got a job), and finished ingest jobs and protocol v2 reports after 30 days, in short batches. Finished rows used to stay for ever.
- Accepting a quarantined sensor report marks it accepted only once it was applied: a failed apply used to leave an item accepted and never applied. The item is claimed while it applies; a second accept or a discard meanwhile answers 409, and a failed apply leaves it pending to be accepted again.
- Migration `003364_quarantine_apply_claim`: `sensor_result_quarantine.applying_at`.
