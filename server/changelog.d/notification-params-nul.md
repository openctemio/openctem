### Fixed: a notification whose values hold a NUL character is no longer lost

- PostgreSQL refuses the NUL character in jsonb, so a notice whose message values carried one
  (for example a finding title with a NUL byte from a scanner) failed to insert. NUL is now
  removed from every message value before it is stored; the English title and body are
  unchanged.
- Docs: server/docs/architecture/notification-system.md#message-codes
