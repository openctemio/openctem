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
export type CIGateOverride = S['internal_infra_http_handler.CIGateOverrideResponse']
export type CIGateOverrideRequest = S['internal_infra_http_handler.CIGateOverrideRequest']

export type CIProvider = 'github' | 'gitlab'
export type CIVerdictFilter = '' | 'pass' | 'fail' | 'none'
