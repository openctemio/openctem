### Added: task logs follow a running task live

- The Logs dialog of a run task re-reads the log every 3 seconds while the task is queued or running, follows the newest line while you are at the bottom of the list, and reads once more when the task finishes so its last lines show. A running task with no lines yet says it is waiting for them instead of "No logs from this task". No API or database change.
