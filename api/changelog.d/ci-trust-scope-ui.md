### Added: CI trust and scope in the console

- The CI trust form has "Trust and add to scope". It is on by default for someone who may change scope, and off and explained for anyone else.
- Each trust card lists its repository scope entries. Each entry shows "Seen in a verified pipeline" (with the repository and time) or "No verified pipeline yet", and says when a person removed it or when it is waiting or could not be added.
- A trust saved before the option existed offers "Add these repositories to scope" to someone who may change scope.
- On Scoping, an entry a CI trust manages says "Managed by the CI trust …" with its evidence. Its only action is to open the trust. Every repository entry offers "Set up CI for these repositories".
- Scoping › Settings has the opt-in "Require proof for CI scopes".
- The trust list API returns every trust's `scope_entries` from one read. For a caller whose data scope does not reach the evidence's repository, its repository and run are left out (the time stays), on the list and the detail alike. The scope entry's `managed_by` no longer names the repository.
