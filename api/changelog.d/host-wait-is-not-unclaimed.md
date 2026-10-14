### Fixed: a scan waiting for its hosts is no longer ended as "no sensor picked up this run's work"

- A run whose work waits while another task of the organization scans the same hosts is no longer failed after an hour (four for a scheduled run) as unclaimed with NO_SENSOR, a reason that is never retried. Once its hosts are free, the usual rule applies again.
