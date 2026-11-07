### Security: shared mail providers' addresses are never offered as yours

- The address classifier knows the Microsoft 365 Exchange front ends (Exchange Online, autodiscover, mail protection) as shared ranges, and the network names and host suffixes of the major shared mail and SaaS providers. The addresses `mail.*` and `autodiscover.*` names resolve to there are third-party on the Decisions card: never offered, never added automatically, passive checks only, and capped to web ports by the active-scan gate, even before their network lookup ran.

### Behaviour change: decide the addresses your names resolve to in bulk

- Attack surface > Discovery > Decisions: every group and list of the addresses card has checkboxes, "Select all" (and every waiting address past the list), "Add selected (as ranges)" and "Not ours". Chosen addresses next to each other become one range that holds only the chosen addresses. Each group offers "Add all N (as ranges)" and "Not ours". The per-address Add button is gone.
- The confirmation lists the network owners and counts of the selection and flags third-party addresses; they are left out unless the person ticks them in, and then each is its own exact entry.
- The card opens with a summary: added automatically (yours), third-party (never scanned), and how many need you.
- `POST /api/v1/easm/suggestions/addresses/add` and `/reject` take `groups` and `all_waiting` beside `addresses` (up to 2000 addresses); `include_shared` now admits several third-party addresses.

### Added: where the network lookup of an address stands, with a retry

- An address with no network data says whether its sensor lookup (`lookup.asn`) is still running, found no routing data, or failed. A failed lookup reads "Network lookup failed", or "Network lookup failed (source unavailable)" when the routing data source did not answer, with "Retry lookup" (`POST /api/v1/easm/suggestions/addresses/lookup`, `assets:write`), which makes the lookup due again for a sensor. The platform itself looks nothing up.
