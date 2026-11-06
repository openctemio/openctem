### Fixed: the run page names a failed proxy as the cause of a coverage gap

- A host a sensor could not judge because the scan's proxy failed (gap reason `proxy_unavailable`) is now kept in the task's coverage gaps and its summary, and the run page shows it with its own label (en, vi), instead of dropping it.
