### Fixed: the attack surface Review badge counts only what waits for a decision

- The Review tab and sidebar badge counted a suggested name rule for every discovered name (names that are already in the inventory and need no decision), up to 50, plus an addresses card that offered nothing. It now counts the name rules over the names that need review (`needs_review`, `candidate`), the same names the Review tab lists, and a card only when it offers something. `GET /api/v1/easm/suggestions` gains `name_rules`.
- Addresses that the organization's unclassified-scans mode already checks (a known network that is not shared) are decided by the server and returned in `checked_addresses` / `checked_count`; they are no longer counted as waiting.
- Shared, CDN and hosting addresses are one quiet line on the Review tab ("need no decision") and never show open ports, which are the provider's. A card that offers nothing no longer hides the "Nothing to decide" state.
