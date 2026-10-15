### Fixed: a renamed repository keeps its asset, and repository import and CI share one asset

- CI found a repository asset by name, so renaming or transferring a repository made a new asset: the
  findings, branches, baseline, gate policy and coverage expectation stayed on the old one, and every pull
  request of the renamed repository was blocked for lack of a baseline. Repository import named assets
  `org/repo` while CI named them `github.com/org/repo`, so one repository was two assets. Both now find a
  repository by its code host and immutable repository id (GitHub repository id, GitLab project id, Bitbucket
  repository UUID) first; a renamed repository keeps its asset and takes the new name; repository import
  names new assets `host/path` and adopts an asset CI created.
- Existing duplicates are merged by `repomerge` (separate change).
