### Fixed: e-mail channel errors on create, and a slow relay no longer ends in 504

- `POST /integrations/notifications` (and the update) with e-mail credentials that are not the JSON object of the relay settings, for example a bare address, answered 500. It now answers 400 `BAD_REQUEST` naming the expected fields (`smtp_host`, `smtp_port`, `from_email`, `to_emails`).
- The connection test that runs on create and update (and on `POST /integrations/{id}/test-notification`) is bounded to 15 seconds. A relay or webhook that never answers made the request end in 504 `TIMEOUT` while the channel was saved; the channel is now saved with status `error` and code `INTEGRATION_UNREACHABLE`, and the request answers 201 with that state, as for every other failed test.
- Docs: server/docs/architecture/notification-system.md
