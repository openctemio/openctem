### Fixed: editing a scan that inherits its profile's rule sources

- Saving an edited scan whose rule sources are inherited from its profile no
  longer fails with "rule_sources must be one of: both platform tenant". An
  empty value means "inherit"; other values are still checked.
