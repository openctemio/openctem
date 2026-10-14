### Security: a cloned scan keeps its intensity and starts paused

- `POST /api/v1/scans/{id}/clone` dropped the scan's intensity, so a passive scan cloned as active and its copy probed hosts the original never touched. The copy now keeps the intensity.
- A copy now starts paused (the console always said so; the API started it active, so a scheduled copy ran on its own). Resume it to start its schedule. Cloning also runs the create's intrusive-proof and scope tier checks, and is recorded in the audit log.
