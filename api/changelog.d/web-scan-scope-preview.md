### Added: New Scan checks scope while you type, and picks a coverage level (web)

- New Scan and Quick scan send the targets to `POST /api/v1/scope/check`
  (debounced) and show each refused target with its reason and the fixes the
  server offers (add to scope, allow for N days, request access, approve,
  verify the domain, ...). Nothing is dispatched by the preview.
- New Scan has a coverage level: this host only, host and its subdomains, or
  also their IPs. Subdomains and addresses come from the inventory; each added
  target goes through the same scope check (an address needs its own IP
  scope entry).
- A scan create, edit, quick scan or trigger refused with
  `TARGET_OUT_OF_SCOPE` lists `details.refused[]` the same way, with the
  fixes, instead of one long toast.
