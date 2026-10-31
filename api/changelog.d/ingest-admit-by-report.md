### Fixed: a sensor report refused part-way by a full ingest queue

- Queue back-pressure on sensor results is decided per report: the first segment of a new report is checked against `INGEST_MAX_PENDING_PER_TENANT`, further segments of a report already admitted against twice that, so a busy queue no longer leaves half-received reports that expire and never count.
- A `429 queue-full` to a sensor now carries a `Retry-After` computed from how fast the organization's jobs drain (5 s to 5 min), jittered so sensors refused at the same moment do not all retry together. It was a fixed 30 s.
- New gauge `openctem_ingest_queue_oldest_seconds{lane}`: how long the oldest claimable ingest job has waited, the import lag per lane.
