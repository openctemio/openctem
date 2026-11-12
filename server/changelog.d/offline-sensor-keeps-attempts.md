### Fixed: a sensor that goes offline no longer uses up its tasks' attempts

- A scan task whose sensor went offline (a network or DNS outage on the sensor's host) lost a dispatch attempt each time its lease ended. With one sensor that kept dropping off, every task spent its 3 attempts on `infra.sensor_offline` in minutes and the step failed hours later. Such a task now waits without using an attempt, and its state reads "waiting for sensor <name> to come back". It runs again when an eligible sensor is online.
- A task that takes its sensor offline every time still ends: after 8 waits each lost lease counts again. A lost lease of a sensor that is still online counts as before.
- A task moved to another sensor after an infrastructure failure now waits out the re-queue back-off (5 seconds, doubling to 5 minutes) instead of being offered again at once.
