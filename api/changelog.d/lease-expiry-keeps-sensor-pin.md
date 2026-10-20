### Fixed: a command addressed to one sensor stays with that sensor after a lease expires
- A command sent to one sensor on purpose (a config update, a connector scan pinned to one runner) went back to the pool unpinned when its lease expired, so another sensor of the tenant could run it. It now returns to pending still addressed to its sensor; routed scan work and unpinned commands are unchanged.
- Adds `commands.pinned_sensor_id`, recorded when such a command is claimed (migration 003141).
