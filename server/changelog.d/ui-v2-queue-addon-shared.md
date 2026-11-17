### Changed: the queue add-on moves into the shared web layer (redesign branch)

- The decision controls, reason dialog, decide-by date, status region, queue card and queue empty states move
  from `web/src/features/queue` to `web/src/features/shared/components/queue` and are exported from
  `@/features/shared`, the layer the tenant app and the platform console both import. The console's queues use
  the same parts; nothing is copied.
- No behaviour, text, permission or confirmation changes.
- Docs: `web/docs/ui-style-contract.md` ("Queues") names the new place.
