### Fixed: "Mark all read" now clears every notification

- A notification dated ahead of the database clock stayed unread forever after "Mark all read" (the unread count compares its time with the read-all watermark). The store now clamps a notification's time to the database clock on insert and on a coalescing update, and "Mark all read" sets the watermark to the later of now and the newest notification time in the organization. The bell also drops its badge at once instead of waiting for the refresh.
- No migration and no data change: a stored future-dated notification is cleared by the next "Mark all read" (the watermark covers the newest notification time).
- Docs: none (bug fix, no behaviour change to document)
