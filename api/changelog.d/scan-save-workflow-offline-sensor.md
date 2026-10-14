### Fixed: a workflow scan can be saved or scheduled while its sensor is offline

- The New Scan wizard disabled Save and Schedule for a workflow scan whose sensors were only offline at that moment, although the API saves such a scan and its runs wait for a sensor. It is now a warning when the scan is saved for later or scheduled; a scan set to run now is still stopped, and a step no sensor has at all still blocks.
