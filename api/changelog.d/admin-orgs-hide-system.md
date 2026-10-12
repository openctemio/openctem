### Fixed: the admin console no longer lists or counts the internal System organization

- `GET /api/v1/admin/tenants` leaves the platform system tenant out of its rows and total; `include_system=true` lists it.
- The console overview no longer counts it as an organization, nor as one without an owner.
