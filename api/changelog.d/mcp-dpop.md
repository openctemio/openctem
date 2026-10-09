### Security: DPoP proof-of-possession for AI application tokens

- MCP clients that support DPoP (RFC 9449) get tokens bound to their own
  key: every token refresh and every MCP request must carry a fresh proof
  signed by that key, so a copied token is useless on its own (RFC-062).
  Proofs are ES256 or EdDSA, single use (remembered in Redis), within 60
  seconds.
- Organizations can require DPoP (`require_dpop` in the MCP policy); bearer
  connections then stop working.
- Migration `001386_mcp_oauth_dpop`.
