### Changed: API CI generates the OpenAPI spec once instead of in each of the 14 test shards
- A new `OpenAPI spec` job uploads the spec; the test and least-privilege shards download it. About 27 runner-minutes less per merge group, same wall time.
