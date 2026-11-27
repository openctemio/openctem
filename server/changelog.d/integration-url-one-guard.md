### Security: integration URLs are checked by the same address guard as outgoing requests

- An integration's base URL typed as an address (`https://100.64.0.1`, a NAT64 or 6to4 form of an internal address, the IETF protocol range) was checked against a shorter list than the guarded HTTP client uses, so it was accepted and only failed when called. It is now refused at once by the same guard, as a host name resolving there already was. Private ranges an operator opened stay open, as at dial time.
- A host name that does not resolve is now reported as "URL host does not resolve" instead of "resolves to a blocked address".
- Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) stay allowed everywhere, as the shared address scope defines them.
- Docs: none (the egress policy documented in the security guide is unchanged; this applies it at validation time too)
