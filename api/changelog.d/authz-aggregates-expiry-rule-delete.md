### Security: counts follow the reader's data scope, expired team memberships stop granting scope, and scope-rule delete is capped

- `asset_count` on access groups, the business unit rollup counters, `/scoping/summary` asset counts, `/attack-surface/stats` breakdown and average risk, and the exposure-chain summary now count only the assets the caller can see. Organization-wide configuration totals are unchanged and listed in the authorization matrix.
- A team membership past its end date no longer grants asset scope while waiting for the expiry controller (migration `002898`; it rebuilds the scope rows once).
- A caller limited to their scope can delete a scope rule only when every asset of its team and of the rule is in their scope. Deleting a rule rebuilds the scope rows of that organization only, not every organization's.
