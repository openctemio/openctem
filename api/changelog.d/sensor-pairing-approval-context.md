### Security: sensor pairing approval names and binds the organization

- The pairing review now states the organization the sensor joins, and the approval must name the same organization: an approval sent after the approver switched organization is refused (`409 ORGANIZATION_MISMATCH`) before re-authentication, and audited.
- The review shows the request's address with its network class (private or public, and the edge or hosting provider when known) next to the approver's own address, the product, the SDK version and the request's age. The console warns, where the sensor showed the code, never to approve a code someone else sent.
- Rejecting a request no organization claimed yet now needs its code, like an approval (`POST /api/v1/sensor-pairings/{id}/reject` takes `{"code": "..."}`).
- The failed code lookup that locks a user's lookups is audited (`sensor.pairing_lookup_locked`, high).
- No migration. API clients that approve pairings must send `organization_id` (the value the lookup returns).
