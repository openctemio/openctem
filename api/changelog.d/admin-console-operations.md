### Added: an Operations health page in the platform admin console

- Operations > Health (`GET /api/v1/admin/operations`) shows the build and schema drift, database and Redis latency and the connection pool, the work queues (sensor jobs, scan runs past their deadline, notifications), sensors by health and SDK version (below the minimum flagged), and each background job's last run and errors. It needs no Prometheus server.
- The overview's platform problems link to it.
