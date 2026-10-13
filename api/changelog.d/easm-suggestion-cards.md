### Added: attack surface suggestion cards

- New `GET /api/v1/easm/suggestions`, read only and narrowed to the caller's
  data scope. It returns the scope decisions that still need a person, one
  card each:
  - `addresses_behind_names`: the addresses your in-scope names resolve to,
    as one grouped suggestion instead of a review row per address. Shared,
    CDN and other organizations' addresses are listed apart with the reason
    and are never offered. An address whose network is unknown is counted
    as such and never presented as safe.
  - `confirmed_out_of_scope`: assets a person confirmed that no scope entry
    covers.
- Accepting a card is an ordinary bulk add of exact scope entries. Nothing
  is ever added automatically.
