### Added: the sensor drawer and a waiting scan say when a sensor stopped claiming because its storage is full

- The sensor drawer has a Local storage section (whether it claims new jobs, store usage against its quota, disk level, what takes the room, last cleanup) and a health check of the same name. A sensor that stopped claiming shows a critical "Stopped claiming new jobs" problem with the fix; the sensor's own reason is behind "Show the error". The job slots caption says so instead of "4 slots free".
- A waiting scan task explains "Sensors that could take it but stopped claiming new jobs because their local storage is full", and the per-sensor list gives each reason in words instead of its code.
- A key-bound sensor shows "Signing key (key-bound identity)" instead of an API key prefix.
