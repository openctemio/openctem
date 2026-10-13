### Fixed: a web-scoped step a sensor cannot keep to fails once, with its own code

- A scan step whose job has a web scope (the tenant excluded a path on a target host) and whose sensor's tool cannot keep to it now fails with `WEB_SCOPE_UNSUPPORTED` (class `placement`) and the sensor's message, instead of the generic `COMMAND_FAILED`, and is never retried: the same sensor would fail the same way. The run ends `partial` when other steps completed, as for any failed step.
- nuclei keeps to a web scope from sensor releases that include it, on sensors whose tool sandbox confines the network (the sensor container started with the seccomp profile in the sensor's `docker/seccomp`).
