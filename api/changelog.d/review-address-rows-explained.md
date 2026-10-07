### Added: an address in the review queue says why it waits and how to fix it

- An IP address (or a service on one) stays in review even when every name
  that resolves to it is in scope: names never grant their addresses
  (RFC-054 §4.3). Its row in `GET /api/v1/easm/candidates` now carries:
  - `resolved_from`: the in-scope names that resolve to it (within the
    caller's data scope);
  - `network`: the ASN and organization already held for it, whether it is
    shared CDN or cloud space, and whether the organization matches;
  - `hint: ip_needs_ip_entry`;
  - `fixes` the caller may take through the normal scope entry path: add the
    address, add the /24 or /48 around it (only when the ASN organization
    matches and the space is not shared), or, for a member, request a one-off
    entry. Shared CDN or cloud addresses get no fix.
- Evidence from a sensor shows the sensor's name (`source_label`) instead of
  its id; a platform sensor shows as "platform sensor", and another
  organization's sensor is never named.
