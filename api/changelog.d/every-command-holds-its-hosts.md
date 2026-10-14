### Fixed: a scan no longer waits as "should start shortly" behind a scan of the same hosts

- Every command now gets its host keys when it is created, whatever path built it: quick and single-scanner scans, zone fan-outs, validate, retest and platform jobs, not only workflow chunks. The keys come from the same politeness function the sensor uses, and are sent in the payload.
- A command whose hosts another task of the organization is scanning is no longer offered to a sensor that would hand it back ("its hosts are busy on this sensor") again and again. A free slot takes other work instead, and the task shows "Another task is scanning one of its hosts".
- A follow-up of unfinished targets holds only the hosts of its remaining targets.
- Pending commands queued before this change get their keys on start (the stored keys only; their payloads are not rewritten).
- A local filesystem path (a code scan of `.` or `/src`) is on the running sensor's own disk and holds nothing back.
