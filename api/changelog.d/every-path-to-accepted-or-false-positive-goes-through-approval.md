### Security: every path to an accepted risk or a false positive goes through approval

- **Mark duplicate** no longer carries a false positive or risk acceptance onto
  another finding, or closes an open finding under one. A merge is refused with
  409 when exactly one finding is under such a decision, or the two differ,
  whatever the caller holds. Before, one person with `findings:triage` and
  `findings:approve` could fold a low accepted finding into an open critical
  one, which then became accepted with no approval. Request the decision on the
  finding itself.
- **VEX documents uploaded to `POST /api/v1/findings/import`** under
  `INGEST_VEX=enforce` now create a pending false-positive request (actor
  `vex`, needs one more sign-off) instead of setting `false_positive`. The
  response field `vex.closed` is now `vex.requested`; the audit metadata
  `vex_closed`/`closed` are `vex_requested`/`requested`.
- **Exposures and leaked credentials:** the two-approver rule for accepting or
  dismissing a high or critical exposure reads the highest severity it ever had
  (`exposure_events.peak_severity`, migration `002896`, nullable, no backfill,
  only raised). Re-ingesting the same exposure with a lower severity no longer
  lets one approver accept it alone.
