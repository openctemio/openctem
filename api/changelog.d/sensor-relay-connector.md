### Added: relay connector, the platform side of the sensor relay

- `openctem-sensor-relay connector` runs next to the API on the private network and dials the relay with a certificate pinned for its realm. It opens each sensor's sealed request with the ingest key and replays it to the API's sensor routes, where signature, nonce, clock and tenant checks run as for a direct sensor. It then seals the signed answer to the sensor's key (RFC-116).
- Only `/api/v2/sensor/` paths are forwarded; any other path gets a sealed 403 without the API being called. Only allowlisted headers pass in each direction: client-address headers and cookies never reach the API, and `Set-Cookie` never reaches the sensor.
- New operator commands: `ingest-keygen`, `response-keygen` and `ticket-keygen` create 0400 key files and print their public halves. `ticket` mints a sensor's relay ticket, for use until the API issues tickets.
- The connector sets `X-Relay-Sensor` to the route's sensor id on every request it replays; the API refuses a signed request whose verified signing sensor differs. The connector refuses an API URL with a path prefix (the sensors sign the request path).
