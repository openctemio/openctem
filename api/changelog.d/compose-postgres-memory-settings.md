### Changed: the Compose stack sizes PostgreSQL for its host

- The bundled PostgreSQL in `api/deploy/docker-compose.yml` ran with the
  built-in defaults: 128 MB `shared_buffers`, 4 MB `work_mem` and a
  `random_page_cost` meant for spinning disks.
- It now starts with settings for an 8 GB host: 1 GB `shared_buffers`, 3 GB
  `effective_cache_size`, 16 MB `work_mem`, 256 MB `maintenance_work_mem`,
  `random_page_cost` 1.1, 2 GB `max_wal_size` and a 256 MB `/dev/shm`.
  Override them with `PG_SHARED_BUFFERS`, `PG_EFFECTIVE_CACHE_SIZE`,
  `PG_WORK_MEM`, `PG_MAINTENANCE_WORK_MEM`, `PG_RANDOM_PAGE_COST`,
  `PG_MAX_WAL_SIZE` and `PG_SHM_SIZE` (see `.env.example`).
- Measured on a 525k-finding tenant with 2 PostgreSQL CPUs: an interactive
  mix of list and stats reads at 10 users went from 12.9 to 17.7 requests/s,
  and the median latency from 370 ms to 223 ms.
- Upgrade note: on a host with less than 4 GB of memory, set
  `PG_SHARED_BUFFERS=256MB` and `PG_EFFECTIVE_CACHE_SIZE=768MB` before the
  next `up`.
