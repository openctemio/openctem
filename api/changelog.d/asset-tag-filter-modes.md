### Added: asset tag filter with any, all and exclude

- `GET /assets` takes `tags_mode=any|all` (any by default) and
  `exclude_tags=` next to `tags=`. System tags (program links) match too; a
  non-owner matches or excludes a system tag only through programs not
  hidden from them.
- `GET /assets/tags` lists the tags most used first, takes `q` for a
  substring search and, with `include_system=true`, also returns the system
  tags the caller may see. Both lists stay within the caller's tenant and
  data scope.
