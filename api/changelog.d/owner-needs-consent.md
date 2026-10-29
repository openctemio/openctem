### Behaviour change: an existing account no longer becomes an organization owner without consent

- Creating an organization from the console (`POST /api/v1/admin/tenants`) with an owner email that already has an account now answers 409. Before, that person silently became the owner of an organization they never asked for and was not told. The person can create the organization after signing in.
- Approving an access request attaches an existing account as owner only when the requester confirmed the address by email. Without a mail server nothing is confirmed, so anyone could file a request naming someone else's address; that approval is now refused with 409. A confirmed existing account is emailed that the request was approved.
- The operator command (`bootstrap-admin -org-*`) keeps working with an existing account. The internal provisioning API is unchanged.
