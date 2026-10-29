### Added: a sensor's host pressure narrows what it is given, and the sensor page shows it

- The heartbeat's load report may carry `resources.pressure` (level `ok`, `elevated` or `overloaded`, stall percentages, load per CPU, noisy-neighbour flag) and `capacity.launches_held`, `tools_running` and `transient` counters. All are optional; a sensor that sends none behaves as before.
- While the report is fresh, an overloaded sensor is given no new scan when it already holds one (at most one when idle) and an elevated sensor at most one; selection prefers less pressured sensors. The report can only lower what dispatch offers, and its values are clamped.
- A task waiting on such a sensor says `sensor_overloaded` (the sensor's host is overloaded) instead of a plain busy.
- The sensor page has a Host pressure section, with a warning when other programs on the host use most of its CPU.
