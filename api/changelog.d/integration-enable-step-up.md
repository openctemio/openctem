### Security: re-enabling an integration needs a recent sign-in; connection tests are rate limited

- `POST /integrations/{id}/enable` now requires step-up (a recent sign-in), like creating, changing and disabling an integration: enabling restarts outbound data to the destination.
- `POST /integrations/test-credentials` is limited to 10 a minute per tenant (burst 5), so it cannot be used to probe hosts and ports.
- The unused service listers `ListPublic` and `ListHighRisk`, which ignored data scope, are removed; a test keeps them off the repository interface.
