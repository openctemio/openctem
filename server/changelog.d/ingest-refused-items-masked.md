### Security: a finding refused before ingest is masked on the import receipt

- A protocol v2 finding that names no asset of its segment is refused before ingest and booked on the run's receipt as a rejected item. Its title was stored as the tool sent it, so a secret scanner's raw match or a full e-mail address in the title was kept in plain text and shown at `GET /api/v1/findings/imports/{id}/items?disposition=rejected` to any member with `findings:read`, outside the reveal permission, its step-up and its audit record. The item key was a hash of that raw title.
- The refused findings are now masked the way an ingested report is (secret values and the local part of e-mail addresses) before the item is built, so the stored title and the item key hold the masked text. Items written before this change are not rewritten; they expire with the receipt's retention.
- Docs: server/docs/architecture/ingest-receipts.md
