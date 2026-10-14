### Security: changing CI trust needs a recent sign-in

- Creating or changing a CI trust configuration (`POST /api/v1/ci/trust-configs`, `PUT /api/v1/ci/trust-configs/{id}`) and changing the CI settings (`PUT /api/v1/ci/settings`) now need step-up, like a break-glass. A trust configuration decides which pipelines may send results that the gate judges, and the settings can let CI sensor keys back in. Without step-up, a stolen session could add the attacker's own CI organization.
- The console asks for the second factor and retries the request. Deleting a configuration only withdraws trust and is unchanged.
