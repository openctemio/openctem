### Security: an SSO domain is claimed by one organization

- Verifying an SSO domain that another organization already holds is refused
  (409, the other organization is not named). After the holder's DNS proof
  lapses, another organization must wait 7 days before it can verify. A
  partial unique index enforces the rule under concurrent verifications
  (migration 001303).
- Adding a domain now refuses every public suffix (including private-section
  ones such as `github.io` and the names under them), a longer list of consumer
  mailbox providers and the disposable-address services, embedded at build
  time.
- **Upgrade note:** migration 001303 drops nobody's access. When two or more
  organizations had the same domain verified for SSO, their rows are flagged
  `claim_conflict` and keep working. The console shows a "Claim conflict"
  badge; remove the wrong claim. To find them:
  `SELECT tenant_id, domain FROM verified_domains WHERE claim_conflict;`
