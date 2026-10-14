### Changed: the "addresses your in-scope names resolve to" card explains its value and shows evidence

- The card says why it matters (only the names are scanned today, so a
  service on the address without a name is missed) and lists, for each
  address, the open ports seen on it or on its names and the other names
  that resolve to it (`ports`, `other_names`).
- An address inside an announced prefix of the organization's own seeded
  network offers that prefix as one CIDR rule (`prefix_rules`), only when the
  platform guardrails accept it; adding it goes through the scope service
  (step-up, approvals, audit).
- Shared, CDN and hosting addresses stay out of the count, listed as
  "Shared, not offered". "Not ours" records a rejection, so the addresses are
  never suggested or scanned again (undo on the toast). "Not now" hides the
  card on the overview for 30 days, or until it shows a new address, port or
  name. While unclassified assets get low-impact checks, only addresses whose
  network is unknown wait for a decision.
