### Security: a revoked sensor can no longer be disabled and then re-activated

- `POST /api/v1/sensors/{id}/disable` on a revoked sensor now answers 403, like activate and the status edit already did. Before, disabling a revoked sensor turned it into a paused one that activate could bring back, and a legacy bearer-key sensor would then authenticate again with its old key. Revoked is final; install a new sensor (or re-pair) instead.
