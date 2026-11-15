### Added: the analyze job can carry the masked bundle inline (`bundle.text`)

- The `openctem.analyze/v1` job schema gains an optional `bundle.text` (a string of at most 196608 characters): the bundle an AI worker reads, masked when `bundle.masked` is true. The placeholder mapping stays on the platform; a worker never receives a secret value. Additive: the contract stays v1 and a job without it is still valid.
- Docs: server/docs/architecture/ai-analyze-contract.md ("The bundle in a job")
