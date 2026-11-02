### Fixed: a task claimed after its run's deadline moved no longer runs 30 s and fails

- When a sensor claims a task, the task's payload `deadline` is now always set to the run's current deadline. Before, it was updated only when that same claim moved the run's deadline. A task created before an earlier claim moved the run therefore kept its creation-time deadline. After hours in the queue that deadline had passed, so the sensor gave the job its least budget (30 s), and the job failed with "context deadline exceeded" as a platform-side coverage failure. No migration.
