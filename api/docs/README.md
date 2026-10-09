# OpenCTEM Engineering Documentation

Documentation for people who develop OpenCTEM. To install, configure, operate
or use OpenCTEM, see [docs.openctem.io](https://docs.openctem.io)
([install](https://docs.openctem.io/install/),
[configuration](https://docs.openctem.io/configuration/),
[operations](https://docs.openctem.io/operations/)).

## Start here

- [Getting started (development)](getting-started.md)
- [Development setup](development/setup.md)
- [Repositories and how the platform fits together](development/repositories.md)
- [Architecture overview](architecture/overview.md)
- [RFCs](rfcs/README.md): design documents and decisions
- [User guide](https://docs.openctem.io/user-guide/): the product from a user's point of view
- Web console: [`web/docs/`](../../web/docs/README.md)

## Development

- [Setup](development/setup.md), [coding style](development/coding-style.md), [testing](development/testing.md), [logging](development/logging.md)
- [Migrations](development/migrations.md)
- [CI/CD and releases](development/ci-cd.md), [versioning and releases](architecture/versioning-and-releases.md)
- [Pre-commit and security tooling](development/pre-commit-security.md)
- [Asset type registry](development/asset-type-registry.md), [relationship types](development/relationship-types.md)
- [Makefile reference](MAKEFILE.md), [Swagger annotations](SWAGGER_GUIDE.md)

## API

- [REST API overview](api/README.md) and [reference notes](api/endpoints.md) (the full spec is served at `/docs` and `/openapi.yaml`)
- [API conventions](architecture/api-conventions.md), [list query contract](architecture/list-query-contract.md)
- [Tenant API keys](architecture/api-keys.md), [MCP server](architecture/mcp-server.md)
- [Credential import](api/credential-import.md), [suppressions](api/suppressions.md)

## Architecture

**Foundations**
- [Overview](architecture/overview.md), [clean architecture](architecture/clean-arch.md), [project structure](architecture/project-structure.md)
- [Module coupling](architecture/module-coupling-and-decoupling.md), [plans and limits](architecture/plans-and-limits.md), [idle Free workspaces](architecture/idle-workspaces.md)
- [Organization settings](architecture/organization-settings.md), [database notes](architecture/database-notes.md), [row-level security rollout](architecture/rls-rollout.md)
- Decisions: [ADR-001 standard net/http](architecture/decisions/001-use-stdlib-http.md), [ADR-002 protocols](architecture/decisions/002-multi-protocol.md), [ADR-003 connectors](architecture/decisions/003-connector-pattern.md), [ADR-004 finding provenance](architecture/decisions/004-finding-provenance.md)

**Identity and access**
- [Authorization matrix](architecture/authorization-matrix.md) (the canonical authorization model), [access control rules](architecture/access-control-rules.md)
- [User onboarding](architecture/user-onboarding.md), [two-factor authentication](architecture/user-two-factor-authentication.md), [step-up re-authentication](architecture/step-up-reauth.md)
- [SSO authentication](architecture/sso-authentication.md), [multi-tenant Entra ID model](architecture/multi-tenant-entraid-model.md), [SAML SSO](architecture/saml-sso.md), [SCIM provisioning](architecture/scim-provisioning.md)
- [Audit hash chain](architecture/audit-hash-chain.md)

**Assets and scope**
- [Asset inventory v2](architecture/asset-inventory-v2.md), [asset schema](architecture/asset-schema.md), [asset properties schema](asset-properties-schema.md)
- [Asset identity resolution](architecture/asset-identity-resolution.md), [IP/hostname correlation](architecture/asset-ip-hostname-correlation.md), [deduplication](architecture/deduplication.md), [source priority](architecture/asset-source-priority.md)
- [Asset ownership](architecture/asset-ownership.md), [asset deletion](architecture/asset-deletion.md), [asset group recalculation](architecture/asset-group-recalculation.md), [criticality propagation](architecture/criticality-propagation.md)
- [Data provenance](architecture/data-sources.md), [component relationships](architecture/component-relationship-best-practices.md), [web surface](architecture/web-surface.md)
- [Scoping overview](architecture/scoping-overview.md), [active-probe gate](architecture/active-probe-gate.md)
- [EASM](architecture/easm.md), [EASM DNS checks](architecture/easm-dns-checks.md), [certificate transparency monitoring](architecture/certificate-transparency-monitoring.md), [change detection](architecture/change-detection.md)

**Sensors and scanning**
- [Sensors](architecture/sensors.md), [sensor identity](architecture/agent-identity.md), [sensor pairing](architecture/sensor-pairing.md), [sensor ↔ platform trust](architecture/sensor-platform-trust.md), [signed jobs](architecture/job-signing.md), [result binding](architecture/sensor-result-binding.md)
- [Scan lifecycle](architecture/scan-lifecycle.md), [scan orchestration](architecture/scan-orchestration.md), [scan stages](architecture/scan-stages.md), [scan zones](architecture/scan-zones.md), [scan naming](architecture/scan-naming.md)
- [Tool contract](architecture/tool-contract.md), [tool availability](architecture/tool-availability.md), [secret scanning](architecture/secret-scanning.md)
- [CI runner identity and gate](architecture/ci-runner-identity.md), [shift-left CI scanning](architecture/shift-left-ci-scanning.md), [branch-only findings](architecture/branch-only-findings.md)
- [Scan coverage (Tenable)](architecture/scan-coverage.md), [Tenable.sc connector](architecture/tenable-sc-connector.md)

**Findings and prioritization**
- [Vulnerability model](architecture/vulnerability-model.md), [finding import](architecture/finding-import.md), [finding source interop](architecture/finding-source-interop.md), [finding evidence](architecture/finding-evidence.md), [`not_observed` status](architecture/finding-status-not-observed.md)
- [Global catalog trust](architecture/global-catalog-trust.md), [priority explainability](architecture/priority-explainability.md), [CTEM-ID catalog](architecture/ctem-id-catalog.md)
- [Validation engine](architecture/validation-engine.md), [continuous retest](architecture/continuous-retest.md)

**Mobilization, automation and reporting**
- [Remediation campaigns](architecture/remediation-campaigns.md), [campaign Jira sync](architecture/remediation-campaign-jira-sync.md), [ticketing (Jira)](architecture/ticketing-integration.md), [GitHub Issues ticketing](architecture/github-issue-ticketing.md)
- [Automations](architecture/automations.md), [notification system](architecture/notification-system.md), [SIEM ingest](architecture/siem-ingest.md)
- [CTEM program metrics](architecture/program-metrics.md), [CTEM definition of done](architecture/ctem-dod-checklist.md), [report PDF export](architecture/report-pdf-export.md)
- [API ↔ CTIS decoupling](architecture/api-ctis-decoupling.md)

## How-to (integrations and features)

- [Pair a sensor](how-to/pair-a-sensor.md), [fix a sensor's setup checklist](how-to/fix-sensor-setup-checklist.md)
- [Connect CI pipelines](how-to/connect-ci-pipelines.md), [GitLab CI](how-to/gitlab-ci.md)
- [Verify a domain for EASM](how-to/verify-a-domain-for-easm.md), [EASM monitoring settings](how-to/easm-monitoring-settings.md)
- [Configure Microsoft Entra ID](how-to/configure-entraid.md), [SCIM provisioning](how-to/configure-scim-provisioning.md)
- [Configure Jira ticketing](how-to/configure-jira-ticketing.md), [SIEM forwarding](how-to/configure-siem.md)

## Deployment and operations (repository runbooks)

Install and day-to-day operation are documented at
[docs.openctem.io](https://docs.openctem.io). These runbooks stay with the code
because they change with it:

- [Upgrading from v0.8 to v0.9](operations/upgrade-v0.8-to-v0.9.md)
- [Monitoring and alerting](operations/monitoring.md)
- [Safe deploy and migrations](deployment/safe-deploy-and-migrations.md)
- [Least-privilege database roles](deployment/database-roles.md)
- [Rotating `APP_ENCRYPTION_KEY`](deployment/encryption-key-rotation.md)
- [Docker (development)](deployment/docker.md), [Kubernetes requirements](deployment/kubernetes.md), [Redis](redis-production-guide.md)
