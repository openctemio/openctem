### Changed: tool availability is computed once per decision, not once per tool

- Scan triggers, workflow previews and the coverage planner read the tenant's tool availability (catalog, sensors, zones, grants, manifests) once per decision instead of once per tool, which cuts the database reads of each decision to a fraction. The result is held for that one operation only, so a sensor going offline is seen by the next decision.
