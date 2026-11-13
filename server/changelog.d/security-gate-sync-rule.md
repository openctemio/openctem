### Changed: the security gate does not re-judge what a develop -> next sync merges cleanly

- A pull request into `next` is judged only on the files that differ from git's clean merge of `develop` into `next`, which the gate computes from the commits. Conflict resolutions, edits hidden in the merge and anything not on `develop` still need the maintainer's ack.
- Docs: server/docs/development/ci-cd.md#security-gate
