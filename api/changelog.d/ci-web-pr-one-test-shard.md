### Changed: a web pull request runs one Vitest shard

- `Web tests` on a pull request whose tests are narrowed to the files the change can affect now starts one shard instead of three, saving two runners (each with its own install) per web PR so merge-queue jobs start sooner. The merge queue, pushes to develop, the `ci:full` label, an API contract change and any change that cannot be narrowed keep the three balanced shards. Required check names are unchanged (`Web CI OK`).
