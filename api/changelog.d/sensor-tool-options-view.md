### Added: a sensor's tool options on its Manifest tab

- Each tool on a sensor's Manifest tab lists the options its tool manifest declares, read-only: common options first (request timeout, rate limit, concurrency, retries), then the tool's own, with default, range or values, who may set it (the sensor's configuration only, or a scan too), its safety class (impact, dangerous) and the native flag it maps to. The platform already stores each tool's manifest with the sensor's manifest; nothing new is stored.
