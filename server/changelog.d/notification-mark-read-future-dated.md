### Fixed: "Mark all read" now clears every notification

- A notification dated ahead of the database clock stayed unread forever after "Mark all read" (the unread count compares its time with the read-all watermark). The store now clamps a notification's time to the database clock on insert and on a coalescing update, and "Mark all read" sets the watermark to the later of now and the newest notification time in the organization. The bell also drops its badge at once instead of waiting for the refresh.
- Migration 20261114100000 (`notifications_clamp_future_created_at`) is a data correction: it sets `created_at = now()` on notifications more than a minute in the future (a handful on a live install, none on most). No schema change; the down step does nothing.
- Docs: none (bug fix, no behaviour change to document)
