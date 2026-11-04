### Changed: sensors and connectors must speak CTIS 2.0

- The platform accepts CTIS 2.0 documents only. Upgrade every sensor to v0.36.0 or later and the Tenable connector to v0.2.0 or later together with this release; older ones now show "version unsupported" in the console (they stay connected, but their results are refused). Sensors built on sdk-go older than v0.46.0 show "SDK unsupported".
