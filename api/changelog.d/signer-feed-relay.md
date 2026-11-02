### Security: the job signer signs feed relay rounds only for allowlisted feed origins

- New statement kind of work for the job signer: `command_type` `feed_relay`, the platform tenant id (nil UUID), a platform (instance) sensor, no tool, and feed origins as targets (RFC-142). It is the first step of receiving signed feeds through a platform sensor so the platform needs no outbound access.
- The signer signs such a statement only when every origin is in its own allowlist `SIGNER_FEED_ORIGINS` (default: the official vulnerability feed and release feed origins; `none` turns feed relays off). The nil tenant id is refused on every other job, and a feed relay naming an organization, an organization sensor, a tool or templates is refused.
- **Upgrade note:** nothing to do. Set `SIGNER_FEED_ORIGINS` only when a feed mirror will be relayed.
