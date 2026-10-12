### Removed: the runner sensor type (a sensor API key used from CI)

- CI pipelines authenticate only with their CI provider's OIDC identity (Settings > Scanning > CI pipelines). The `runner` sensor type is gone: creating one is refused (API and console), the console's CI runner role and the `/runners` page are removed (`/runners` redirects to the CI pipelines view), and the `Deprecation` headers sent to runner keys are gone with them.
- The CI upload path no longer poses as a sensor: a CI run's report is submitted as a CI run (`ProducerCIRun`), with no sensor type, exactly as before otherwise.
- Migration `001146` deletes any remaining runner sensors with their keys and per-sensor rows (history rows keep no sensor), then stops accepting the type.
- **Upgrade note:** a CI job that still sends a runner sensor's API key stops working at this upgrade. Move it to OIDC first (`OPENCTEM_TENANT_ID` plus a CI trust configuration; see the how-to "Connect CI pipelines without a stored secret") and delete the `API_KEY` secret from CI.
