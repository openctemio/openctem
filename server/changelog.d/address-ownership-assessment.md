### Added: why an address behind your names is probably yours

- `GET /api/v1/easm/suggestions`: each address on the `addresses_behind_names` card now carries `ownership` (band high, medium, low or unknown, and the evidence: your network seeds, network holder, reverse name, how many of your names point at it, how long, blockers such as a brand-new address). The card lists the strongest first and counts addresses per band (`bands`). Read only: nothing is added to scope automatically (RFC-054 §21).
