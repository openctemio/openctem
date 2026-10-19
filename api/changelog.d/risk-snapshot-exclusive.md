### Fixed: the daily risk snapshot runs on one API replica at a time

- The risk snapshot scans the assets and findings of every organization every six hours. With more
  than one API replica each replica ran it on every tick. It now takes the controller lease like the
  other exclusive controllers, so one replica computes it. Duplicate rows were never possible: the
  snapshot upserts on its unique (organization, day) key, which a new two-replica test also checks.
