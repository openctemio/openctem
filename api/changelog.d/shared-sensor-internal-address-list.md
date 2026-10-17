### Security: one internal-address list for the platform and sensors

- The internal-target checks (shared sensors, and private targets outside scan
  zones) use the ctis `addrscope` list that sensors also use. It adds
  `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, multicast, reserved and
  broadcast IPv4, and IPv6 addresses that carry an internal IPv4 address
  (NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo
  `2001::/32`, IPv4-compatible).
- A range is internal when any of its addresses is, not only its first one
  (`8.0.0.0/6` holds `10.0.0.0/8`).
- Upgrade note: a scan whose targets include such addresses or ranges now
  needs a scan zone that covers them, as private targets already do.
