### Added: review queue address rows explain themselves (web)

- An IP address in the review queue says why it waits ("Names never grant
  their addresses; this IP needs its own scope entry"), which in-scope names
  resolve to it, and the network it sits in (ASN and organization, and
  whether that matches your organization).
- It offers the fixes the server allows the viewer: "Add to scope: <IP>" and,
  when the organization matches, the /24 or /48 around it; a member gets a
  request. Shared CDN or cloud space says it cannot be added and offers
  nothing.
- Evidence from a sensor shows the sensor's name or "platform sensor", and
  "a removed sensor" instead of an id.
- Several scope fixes of one kind now name what each adds.
