### Fixed: a refused scan run says why and what to do

- A run start refused for its targets (`ALL_TARGETS_UNCONFIRMED`, `NO_COMPATIBLE_TARGETS`, `TIER_EXCEEDS`, `INTERNAL_TARGET_OUTSIDE_ZONES`, `NO_RESOLVING_TARGETS`, `INTENSITY_EXCEEDED`, `LIVENESS_NEEDS_HOST_DISCOVERY`) answered with the generic `BAD_REQUEST` code, and a governed scan waiting for approval answered a bare 403 with no message. They now keep their code (and the approval refusal its message: `SCAN_APPROVAL_REQUIRED`, `SCAN_APPROVAL_PENDING`, still 403), and the console's "Run now" toast adds what to do (en, vi).
