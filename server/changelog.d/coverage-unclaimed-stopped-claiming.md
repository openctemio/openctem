### Fixed: a run no sensor picked up because its sensor is full says so

- A scan run (automatic coverage included) that no sensor took within its limit ended with "check that a sensor with this scanner is online" even when the organization's sensor was online, had the scanner and had stopped taking new work because its disk or local storage was full. The run's error now names that cause and points at the sensor host's free space; the sensor page already shows the "stopped claiming" health reason.
- The platform administrators' coverage alert and its log line say "platform or sensor side" instead of "platform side", and the alert states that every check runs on a sensor, never on the platform itself.
- Docs: server/docs/architecture/placement.md, server/docs/architecture/asset-coverage.md
