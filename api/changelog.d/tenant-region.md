### Added: an organization's data region is fixed at creation

- New `DEPLOYMENT_REGION` (for example `eu-central`): every organization created on the deployment
  gets it and keeps it for its life; it is shown when creating an organization and in its settings.
  Organizations created before have no region. Unset: no region is named.
- Migration 002571 adds `tenants.region`.
