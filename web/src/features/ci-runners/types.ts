/**
 * CI runs, CI trust configurations and the CI gate (api RFC-051). Wire types
 * come from the generated OpenAPI types.
 */
import type { components } from '@/lib/api/generated/api.types'

type S = components['schemas']

export type CIRun = S['internal_infra_http_handler.CIRunResponse']
export type CIRunList =
  S['internal_infra_http_handler.ListResponse-internal_infra_http_handler_CIRunResponse']
export type CIVerdict = S['github_com_openctemio_openctem_api_internal_app_cirun.Verdict']
export type CIGateReason = S['github_com_openctemio_openctem_api_pkg_domain_cirun.GateReason']
export type CITrustConfig = S['internal_infra_http_handler.CITrustConfigResponse']
export type CITrustConfigRequest = S['internal_infra_http_handler.CITrustConfigRequest']
export type CITrustRules = S['github_com_openctemio_openctem_api_pkg_domain_cirun.Rules']
export type CIGatePolicy = S['internal_infra_http_handler.CIGatePolicyResponse']
export type CIGatePolicyList = S['internal_infra_http_handler.CIGatePolicyListResponse']
export type CIGatePolicyRequest = S['internal_infra_http_handler.CIGatePolicyRequest']
/** A repository's effective gate settings with per-field provenance (RFC-095). */
export type CIRepositorySettings = S['internal_infra_http_handler.CIRepositorySettingsResponse']
export type CIRepositorySettingField = S['internal_infra_http_handler.CIRepositorySettingField']
/** A repository's gate baseline: findings known when it was recorded do not block. */
export type CIGateBaseline = S['internal_infra_http_handler.CIGateBaselineResponse']
export type CIGateOverride = S['internal_infra_http_handler.CIGateOverrideResponse']
export type CIGateOverrideRequest = S['internal_infra_http_handler.CIGateOverrideRequest']

/** A trust preview: a sample token checked against a draft configuration. */
export type CITrustPreviewRequest = S['internal_infra_http_handler.CITrustPreviewRequest']
export type CITrustPreview =
  S['github_com_openctemio_openctem_api_internal_app_cirun.PreviewResult']

/** The organization's CI settings (OIDC required for CI results). */
export type CISettings = S['github_com_openctemio_openctem_api_internal_app_cirun.Settings']

export type CIProvider = 'github' | 'gitlab' | 'azure_devops' | 'bitbucket' | 'circleci' | 'jenkins'
export type CIVerdictFilter = '' | 'pass' | 'fail' | 'none'

/** CI pipelines: one workflow file of one repository, listed in the fleet in runner mode. */
export type CIPipeline = S['internal_infra_http_handler.CIPipelineResponse']
export type CIPipelineList = S['internal_infra_http_handler.CIPipelineListResponse']
export type CIPipelineDetail = S['internal_infra_http_handler.CIPipelineDetailResponse']
export type CIPipelineStatus =
  | 'retired'
  | 'revoked'
  | 'failing'
  | 'degraded'
  | 'stale'
  | 'running'
  | 'fresh'
  | 'never'
  | 'archived'

/** Coverage: repository x capability from any executor (RFC-051 §10.6). */
export type CICoverage = S['internal_infra_http_handler.CICoverageResponse']
export type CIRepositoryCoverage = S['internal_infra_http_handler.CIRepositoryCoverage']
export type CICapabilityCoverage = S['internal_infra_http_handler.CICapabilityCoverage']
export type CICapability = 'sast' | 'sca' | 'secrets' | 'iac'
export type CICoverageState = 'fresh' | 'stale' | 'never'
export type CICoverageFilter = '' | 'gap' | 'uncovered' | 'covered'

/** Code-host apps that post the CI gate check and pull request comments (RFC-077). */
export type SCMAppList = S['internal_infra_http_handler.SCMAppListResponse']
export type SCMAppInstallation = S['internal_infra_http_handler.SCMAppInstallationResponse']
export type SCMGitLabConnection = S['internal_infra_http_handler.SCMGitLabConnectionResponse']
export type SCMGitLabConnectRequest = S['internal_infra_http_handler.SCMGitLabConnectRequest']
export type SCMCompleteGitHubRequest = S['internal_infra_http_handler.SCMAppCompleteGitHubRequest']

/** A refused CI token exchange and the rule codes that refused it (RFC-051). */
export type CITokenRefusal = S['internal_infra_http_handler.CITokenRefusalResponse']
