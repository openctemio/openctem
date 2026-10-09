### Changed: access requests move to a Requests section in the admin console

- Access requests are now under Requests (`/admin/requests`); the old URL `/admin/organizations/access-requests` is gone.
- The console overview lists waiting access requests (a warning once the oldest has waited two days). `GET /api/v1/admin/overview` returns `requests.access_pending` and `requests.access_oldest_pending_seconds`.
