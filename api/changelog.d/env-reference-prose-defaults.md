### Fixed: the environment variable reference renders prose defaults

- A default that is a sentence with its own code spans (the `CI_RUNNER_*`, `SENSOR_*_VERSION` and database URL rows) was wrapped in another code span, which Markdown cannot nest, so the cell rendered broken. The generator (`make env-docs`) writes such a default as is; a plain value stays a code span.
