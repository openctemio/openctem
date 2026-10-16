### Added: private content packages for an organization and for the instance

- An organization publishes rules, templates and wordlists to itself only (`content:publish`, a recent sign-in;
  namespace = the organization's slug): the artifact becomes one of its content packs, linted, and the statement
  is signed with its content key. Platform super administrators publish to every organization of the instance.
- Revoking a private version revokes every installation of it. Migration 002541 adds the pack links and the
  `content:publish` permission (owners and administrators).
