### Fixed: a chained template stage gets each web service once

- In a workflow, the vulnerability template stage received the same web
  service twice (the HTTP probe's origin URL and the port scan's bare
  `host:port`) plus the name it is served on, and open web ports the probe
  found no HTTP on. A stage that takes web origins now gets each one once,
  as the `http_service` origin; non-web open ports still reach a stage that
  declares open ports (network templates). What is dropped is counted as
  `covered_by_origin` on the stage plan. A chain without an HTTP probe is
  unchanged.
