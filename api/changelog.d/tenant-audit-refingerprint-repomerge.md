### Security: refingerprint and repomerge record what they change in each tenant's audit log

- `refingerprint -apply` writes one `findings.refingerprinted` audit entry per tenant it re-keyed or merged findings in, and `repomerge -apply` one `assets.merged` entry per tenant where it merged repository assets. Each carries the counts, a run id shared by the entries of one run, and the command as actor, so an organization can tell why its findings merged or changed ids.
- A dry run, and a tenant the run did not change, write nothing. If the entry cannot be written the command exits 1.
