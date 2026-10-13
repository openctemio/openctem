### Behaviour change: an active scope entry lets scans reach a pending name

- A discovered name or address that automation left waiting for review
  (`needs_review` or `candidate`) can now be scanned when an active scope
  entry of the tenant covers it, a one-off entry included. Before, the
  pending record refused before any scope check, so adding a one-off entry
  for such a name never helped.
- The record stays pending and the asset does not join the inventory; only
  the entry authorizes the probe. Once the entry expires the record refuses
  again.
- A person's decision still wins: a state a person set (sent back to review,
  dependency, monitor only, rejected), a rejected parent name and a scope
  exclusion keep refusing whatever entry covers the name.
- A service or URL never gets more than its host: when the host asset is
  rejected, a dependency, monitor only or sent back to review by a person,
  probes of its services and URLs are refused with the host's state.
