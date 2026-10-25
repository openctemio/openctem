### Added: nightly authorization matrix suite

- `api/tests/authzmatrix` sends every API route as every kind of principal (owner, admin, member, viewer, custom roles, a data-scoped member, a suspended member, API keys, a sensor, no credential) in two seeded organizations, with its own and with the other organization's ids, and compares the answer with the route's gate. It also runs scenario tests of the role-management API. Runs nightly (`api-authz-matrix.yml`) and locally with `make -C api authz-matrix`.
