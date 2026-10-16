### Added: the platform console API can have its own listener

- New `ADMIN_LISTEN_ADDR` (e.g. `:8081`): the console API (`/api/v1/admin`) is served only on that listener, and the main listener answers 404 for it; the admin listener answers 404 for every tenant, sensor or public route (`/health` excepted). Unset (the default), nothing changes.
- **Upgrade note:** set it only together with routing the console to it (the gateway's admin site and the web console's `ADMIN_API_URL`, shipped with the deployment kits); otherwise the console becomes unreachable.
