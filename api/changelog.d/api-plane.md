### Added: OPENCTEM_PLANE runs one API image as the tenant plane or the console plane

- `OPENCTEM_PLANE=all` (default, self-host) is unchanged: one process serves everything.
- `tenant`: the process never registers the console routes, its main listener answers 404 for `/api/v1/admin` however it is spelled, and it refuses to start with `ADMIN_LISTEN_ADDR` or console database credentials (`DB_ADMIN_USER`, `DB_ADMIN_PASSWORD`). It runs every background job, the administrators' audit forwarder included.
- `admin`: the main listener serves only the console API and `/health`; the process needs the console database role (`DB_ADMIN_USER`) and a loopback or private listen address (or `ADMIN_LISTEN_ALLOW_ALL_INTERFACES=true`), refuses `ADMIN_LISTEN_ADDR`, and runs no background work and no sensor binding. A hosted deployment runs the same image twice, so a code execution in the tenant tier never holds the console's database credentials (RFC-022 revision 21).
