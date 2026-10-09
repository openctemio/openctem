### Security: unauthenticated pairing requests can no longer grow the API memory

- The per-pairing rate limit of the sensor pairing routes (`/api/v2/sensor/pairings/{pairing_id}`, no credentials) used the raw path segment as its key and kept every key for 30 minutes. Any caller could send ids of up to the URL limit and grow the memory of every API replica without bound. A path segment that is not a pairing id is now answered `404 pairing-not-found` before the limiter, and the limiter keys on the parsed id.
