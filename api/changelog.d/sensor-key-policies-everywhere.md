### Security: sensor key policies hold on protocol v3 and on key regeneration

- The organization rule "CI runners must use OIDC" refused a CI sensor key on protocol v2 but not on protocol v3. A standalone sensor with a key-bound identity could still upload over the v3 HTTPS or gRPC binding. v3 calls are now refused the same way (`ci-oidc-required`).
- In an organization that requires key-bound identity, an administrator could still regenerate a bearer key for an existing bearer-key sensor. Regeneration is now refused with `BEARER_KEYS_DISABLED`, like creating a bearer-key sensor. The existing key keeps working until the sensor is paired.
