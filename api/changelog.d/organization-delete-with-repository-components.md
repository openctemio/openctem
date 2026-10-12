### Fixed: an organization that owns a repository with components can be deleted

- Deleting an organization (and so erasing its data) failed with
  "insert or update on table asset_repositories violates foreign key
  constraint" when it owned a repository asset with two or more components or
  branches: the count triggers updated the repository row after the cascade had
  removed its asset. The triggers now skip a repository whose asset is gone
  (migration 001260). `TestDeleteTenantAndUser_EverySchemaTable` passes again
  and a new test deletes committed rows the way a real database holds them.
