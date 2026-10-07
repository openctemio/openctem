### Fixed: every module preset applies, including "minimal"

- Applying a preset whose diff touches more than 50 modules (for example
  "minimal" on an organization with every module on) failed with "too many
  module updates (max 50)". The preset update set is built on the server from
  the preset catalog, so it is now applied as one set without the per-request
  cap; a caller-supplied toggle batch is still capped at 50.
