### Changed: the sensors, scope and compliance pages send fewer requests

- Sensors: the page refreshes the fleet every 15 seconds with one request that carries the fleet stats and only the sensors whose details changed since the previous refresh (`GET /api/v1/sensors?changed_since=<cursor>`; an empty cursor answers the whole fleet). It used to read every page of sensors and the stats separately on each refresh. The server keeps no state: the cursor holds a short digest per sensor, so any change shows, including a state that moves on with the clock. Fleets above 200 sensors get the whole fleet on each refresh, still in one request.
- Scope: `GET /api/v1/scope/targets` and `/scope/exclusions` accept `include=status_counts` and then count every entry the caller may see per status. The page reads its strip, tab and approval counts from two such requests instead of six.
- Compliance: `GET /api/v1/compliance/frameworks?include=stats` carries each framework's stats, so the framework cards no longer send one request each. A framework's stats now refresh after an assessment is saved.

### Security: a framework's stats only for a framework the organization can see

- `GET /api/v1/compliance/frameworks/{id}/stats` answers 404 for another organization's custom framework; it used to return that framework's control count (no assessment data of the other organization).
