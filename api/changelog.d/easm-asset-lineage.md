### Added: how an asset was found, on the asset page

- The asset page and the asset sheet show "How this asset was found": the chain of parent assets from
  the root down to the asset (each one a link), the discovery source and tool, when it was first found,
  and its attribution confidence. The reasons for the confidence stay in the Ownership and scope section.
- New endpoint `GET /api/v1/assets/{id}/lineage` (`assets:read`): the asset and up to 5 ancestors, one
  parent per hop (parent, contains, exposes, serves certificate, resolves to), tenant-bound on every hop
  and never revisiting an asset. An ancestor outside the caller's data scope is returned as a hidden node
  with no name, id or type. The asset view primes it. No migration.
