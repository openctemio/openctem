### Added: sensor protocol v3 pushes across API replicas (RFC-059)

- Command and sensor changes on one API replica now wake the control streams held by every replica, through Redis pub/sub (channel `sensor:v3:wake`). The message is a hint (tenant, sensor); each replica re-reads the database. Without Redis, other replicas see a change at their 30-second re-check.
