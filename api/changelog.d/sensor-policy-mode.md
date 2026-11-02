### Added: sensor local policy summary reports the target mode
- The summary a sensor reports gains `mode` (`allow_all`, `allow_list` or `platform_scope`); unknown values are dropped. The sensor page shows "Targets: allows everything the platform signs" for `allow_all`. Sensors that do not report a mode are shown as before.
