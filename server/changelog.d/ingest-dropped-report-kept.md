### Fixed: a sensor report the worker does not apply keeps its payload

- When the ingest worker's re-check refused a queued v2 report (the sensor was revoked or disabled, or the
  command was taken back and handed out again), its job completed and its stored segment was emptied. The
  report was lost on the platform, and the sensor had already deleted its own copy on the 202.
- Such a job now ends dead with the public code `report_dropped` and keeps its sealed segment for the staging
  retention (7 days). The report still shows `failed`, nothing is applied, and the drop is audited as before.
  An identical re-send of the report re-queues it, so it is applied once the reason is gone.
