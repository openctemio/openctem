### Security: a network range reaches only port scans and network lookups

- Typed-in scan targets were never type-gated: a CIDR (or any literal) went
  to every step of a workflow, HTTP probing and vulnerability templates
  included, and to a single nuclei or httpx scan as written (nuclei then ran
  every template on every address). Every target is now classified (name,
  address, range, URL, service) and each stage gets only the kinds it takes
  (RFC-088). A range, typed in or an inventory network, goes only to port
  scans and network lookups.
- What a step or scanner cannot take is counted with the reason; a step
  left with nothing fails with `INCOMPATIBLE_TARGETS`, a single-scanner run
  with nothing left is refused with `NO_COMPATIBLE_TARGETS`. Inventory
  targets other than ranges keep the stored-type gate.
- No migration and no operator step. Scans that sent a range to nuclei or
  httpx now skip it: add a port-scan step, or scan the addresses.
