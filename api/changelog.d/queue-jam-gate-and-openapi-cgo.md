### Security: the merge queue's security gate reads the merge group's own scan

- In the merge queue the gate compared the pull request's merge-ref scan
  with develop. That ref keeps its last scan, taken against an older base, so
  it still listed alerts develop had since fixed and blocked every entry. The
  gate now reads the merge group's own scan. Pull request runs are unchanged.
- The API image's OpenAPI stage builds with `CGO_ENABLED=0`; it has no C
  compiler, and the spec generator failed to compile the cgo resolver of `net`.
