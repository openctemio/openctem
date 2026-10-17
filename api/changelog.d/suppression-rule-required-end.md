### Behaviour change: every suppression rule has an end date

- A suppression rule ends at most 365 days ahead; a rule created without an end gets 90 days, and the end can no longer be removed. Renewal is a new rule, approved again.
- Migrations 002310–002313 add the review flag (`review_flagged_at`, `review_reason`) and a 90-day default for `expires_at`, give every existing rule without an end 90 days from the upgrade (pending and approved ones are flagged for review and show a "Review" badge), then add and validate `chk_suppression_rules_expires_at_set`.
- **Upgrade note:** rules that never expired before now expire 90 days after the upgrade, and the findings they suppress reopen then unless a new rule is approved. Review the flagged rules in Exceptions.
