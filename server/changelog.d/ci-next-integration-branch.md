### Changed: CI runs for the next integration branch, which takes no migrations

- Pull requests into `next`, its merge queue and pushes to it run the same checks as `develop`. Nothing is published or deployed from `next`.
- A pull request into `next`, or a merge group for it, fails `API CI OK` when a path under `server/migrations/` differs from `develop`'s: schema changes land on `develop`, additive only, and reach `next` through the sync pull request.
- Docs: server/docs/development/ci-cd.md#the-next-integration-branch
