### Added: the run page says why a task waits and how to fix a failed step

- A queued task has a "Why waiting?" toggle: how many sensors can take it and how many are busy, each reason that keeps it from the others with its fix and a link to the page that applies it, and (with `sensors:read`) each sensor's verdict. It reads `GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement` only when opened.
- A failed step in the run map shows its error code, its class, what it means and the fix, with a link. Every error code and placement reason has English and Vietnamese text; a test fails on a code without one.
