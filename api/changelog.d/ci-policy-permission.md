### Added: an AppSec custom role can run the CI gate

- New permission `scans:ci:policy`: create, change and delete CI gate policies and coverage expectations. The routes that need it are `POST`/`PATCH`/`DELETE /api/v1/ci/gate-policies` and `PUT`/`DELETE /api/v1/ci/coverage/expectations/{id}`; they needed `scans:ci:write` before. The owner and admin roles get it, so nothing changes for them.
- `scans:ci:override` (break-glass) can now be put on a custom role. It still needs step-up, and every administrator is alerted when it is used.
- `scans:ci:write` (trust configurations, CI settings, code host connections) stays admin-only: these issue or admit upload credentials.
- The AppSec engineer role template carries `scans:ci:read`, `scans:ci:policy` and `scans:ci:override`.
