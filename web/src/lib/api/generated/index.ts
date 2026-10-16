/**
 * Named access to the generated OpenAPI types.
 *
 * `api.types.ts` is machine-generated and keys its schemas by Go package path
 * (`internal_infra_http_handler.FindingResponse`). Feature code should not
 * reach into that: the key changes whenever a handler type moves package, and
 * the resulting error points at the UI rather than at the rename.
 *
 * This module is a naming layer ONLY. It declares no field shapes — every
 * export resolves to a generated type. If a field is wrong here it is wrong in
 * the server's annotations, which is the point.
 */
import type { paths, components } from './api.types'

export type { paths, components } from './api.types'

/** All schemas the API declares, keyed by their generated (Go) name. */
export type Schemas = components['schemas']

/**
 * The JSON body of an operation's success response.
 *
 * Many list endpoints declare their envelope inline rather than as a named
 * schema, so there is nothing to alias — this reaches the shape through the
 * path + method instead.
 *
 * @example type AssetTypeList = ApiResponse<'/asset-types', 'get'>
 */
export type ApiResponse<P extends keyof paths, M extends keyof paths[P]> = paths[P][M] extends {
  responses: { 200: { content: { 'application/json': infer R } } }
}
  ? R
  : paths[P][M] extends {
        responses: { 201: { content: { 'application/json': infer R } } }
      }
    ? R
    : never

/** The JSON request body an operation accepts. */
export type ApiRequestBody<P extends keyof paths, M extends keyof paths[P]> = paths[P][M] extends {
  requestBody: { content: { 'application/json': infer B } }
}
  ? B
  : paths[P][M] extends {
        requestBody?: { content: { 'application/json': infer B } }
      }
    ? B
    : never

/** The query parameters an operation accepts. */
export type ApiQuery<P extends keyof paths, M extends keyof paths[P]> = paths[P][M] extends {
  parameters: { query?: infer Q }
}
  ? Q
  : never

// ---------------------------------------------------------------------------
// Aliases for the schemas the UI consumes today.
//
// Only endpoints the server actually documents appear here. The spec covers 377
// of 834 registered routes, so a feature missing from this list is missing
// because nothing on the server side describes it yet — not because it was
// skipped. See the PR description for the list.
// ---------------------------------------------------------------------------

// Errors
export type ApiError = Schemas['github_com_openctemio_openctem_api_pkg_apierror.Error']

// Asset types
export type AssetTypeResponse = Schemas['internal_infra_http_handler.AssetTypeResponse']
export type AssetTypeCategoryResponse = Schemas['internal_infra_http_handler.CategoryResponse']

// Asset type registry (RFC-042): GET /asset-types
export type AssetTypeRegistryResponse =
  Schemas['internal_infra_http_handler.AssetTypeRegistryResponse']
export type AssetTypeDefinition =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_asset.TypeDefinition']
export type AssetClassDefinition =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_asset.ClassDefinition']
export type AssetLensDefinition =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_asset.LensDefinition']

// Asset groups
export type AssetGroupResponse = Schemas['internal_infra_http_handler.AssetGroupResponse']
export type AssetGroupStatsResponse = Schemas['internal_infra_http_handler.AssetGroupStatsResponse']
export type GroupAssetResponse = Schemas['internal_infra_http_handler.GroupAssetResponse']
export type GroupFindingResponse = Schemas['internal_infra_http_handler.GroupFindingResponse']

// Components (RFC-070)
export type ComponentPackage =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_component.Package']
export type ComponentSummary =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_component.Summary']

// CTEM cycles — the close-time verdict on each charter success criterion.
export type CtemCycleResponse = Schemas['internal_infra_http_handler.CTEMCycleResponse']
export type CharterEvaluation =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_ctemcycle.CharterEvaluation']
export type CriterionEvaluation =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_ctemcycle.CriterionEvaluation']
export type CriterionOutcome =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_ctemcycle.CriterionOutcome']

// Credentials (leaked-credential inventory)
export type CredentialItem =
  Schemas['github_com_openctemio_openctem_api_internal_app_integration.CredentialItem']
export type CredentialListResult =
  Schemas['github_com_openctemio_openctem_api_internal_app_integration.CredentialListResult']
export type IdentityListResult =
  Schemas['github_com_openctemio_openctem_api_internal_app_integration.IdentityListResult']
export type IdentityExposure =
  Schemas['github_com_openctemio_openctem_api_internal_app_integration.IdentityExposure']
export type CredentialImportResult =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_credential.ImportResult']

// Findings / vulnerabilities.
//
// Named but NOT yet consumed. src/features/findings/api/finding-api.types.ts is
// still hand-written, deliberately: ApiFinding has 124 fields against
// FindingResponse's 139, it is read by dozens of components, and switching it
// is a large enough change to deserve its own review. The 15 fields it is
// missing are listed in the PR description — they include sla_deadline,
// is_internet_accessible, remediation and cisa_kev.
export type FindingResponse = Schemas['internal_infra_http_handler.FindingResponse']
export type FindingStatsResponse = Schemas['internal_infra_http_handler.FindingStatsResponse']
export type VulnerabilityResponse = Schemas['internal_infra_http_handler.VulnerabilityResponse']
export type DataFlowResponse = Schemas['internal_infra_http_handler.DataFlowResponse']
export type BulkUpdateResponse = Schemas['internal_infra_http_handler.BulkUpdateResponse']
// Continuous retest (RFC-039)
export type FindingRetestResponse = Schemas['internal_infra_http_handler.FindingRetestResponse']
export type FindingRetestListResponse =
  Schemas['internal_infra_http_handler.FindingRetestListResponse']
// Finding evidence (masked proof + audited reveal)
export type FindingEvidenceItemResponse =
  Schemas['internal_infra_http_handler.FindingEvidenceItemResponse']
export type FindingEvidenceItemListResponse =
  Schemas['internal_infra_http_handler.FindingEvidenceItemListResponse']
export type RevealEvidenceResponse = Schemas['internal_infra_http_handler.RevealEvidenceResponse']
export type EvidenceItem = Schemas['github_com_openctemio_openctem_api_pkg_domain_evidence.Item']

// Scope (targets / exclusions)
export type ScopeTargetResponse = Schemas['internal_infra_http_handler.ScopeTargetResponse']
export type ScopeExclusionResponse = Schemas['internal_infra_http_handler.ScopeExclusionResponse']
export type ScopeStatsResponse = Schemas['internal_infra_http_handler.ScopeStatsResponse']
export type CheckScopeResponse = Schemas['internal_infra_http_handler.CheckScopeResponse']
export type ScopeCheckResult = Schemas['internal_infra_http_handler.ScopeCheckResult']
export type ScopeBulkOperationResponse =
  Schemas['internal_infra_http_handler.ScopeBulkOperationResponse']
export type BulkCreateScopeTargetsResponse =
  Schemas['internal_infra_http_handler.BulkCreateScopeTargetsResponse']

// Inventory vulnerability matching (RFC-066): an asset's software, its
// matched CVEs and the organization's policy
export type AssetSoftwareListResponse =
  Schemas['internal_infra_http_handler.AssetSoftwareListResponse']
export type AssetSoftwareResponse = Schemas['internal_infra_http_handler.AssetSoftwareResponse']
export type AssetSoftwareMatchResponse =
  Schemas['internal_infra_http_handler.AssetSoftwareMatchResponse']
export type VulnMatchingSettings =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_tenant.VulnMatchingSettings']

// Asset state history ("What changed")
export type StateChangeResponse = Schemas['internal_infra_http_handler.StateChangeResponse']

// Web surface (RFC-056): endpoints under origins, path patterns, the change feed
export type WebEndpointResponse = Schemas['internal_infra_http_handler.WebEndpointResponse']
export type WebEndpointParamResponse =
  Schemas['internal_infra_http_handler.WebEndpointParamResponse']
export type WebEndpointStatsResponse =
  Schemas['internal_infra_http_handler.WebEndpointStatsResponse']
export type WebOriginResponse = Schemas['internal_infra_http_handler.WebOriginResponse']
export type WebPathPatternResponse = Schemas['internal_infra_http_handler.WebPathPatternResponse']
export type WebEndpointEventResponse =
  Schemas['internal_infra_http_handler.WebEndpointEventResponse']
export type WebPathCatalogEntry =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_webendpoint.CatalogEntry']

// Admin console: an organization's audit hash-chain
export type AdminAuditChainStatusResponse =
  Schemas['internal_infra_http_handler.AdminAuditChainStatusResponse']
export type AdminAuditChainRebaselineRequest =
  Schemas['internal_infra_http_handler.AdminAuditChainRebaselineRequest']
export type AdminAuditChainRebaselineResponse =
  Schemas['internal_infra_http_handler.AdminAuditChainRebaselineResponse']
// Admin console: the request-access queue (Organizations > Access requests)
export type AccessRequest = Schemas['internal_infra_http_handler.AccessRequestResponse']
export type AccessRequestList = Schemas['internal_infra_http_handler.AccessRequestListResponse']
export type ApproveAccessRequestInput = Schemas['internal_infra_http_handler.ApproveAccessRequest']
export type ApproveAccessRequestResult =
  Schemas['internal_infra_http_handler.ApproveAccessRequestResponse']
// Limits and feature denies (console System > Limits and an organization's
// limits and modules; the organization Settings > Usage & limits)
export type SelfServiceLimitsResponse =
  Schemas['internal_infra_http_handler.SelfServiceLimitsResponse']
export type UpdateSelfServiceLimitsRequest =
  Schemas['internal_infra_http_handler.UpdateSelfServiceLimitsRequest']
export type AdminLimitsResponse = Schemas['internal_infra_http_handler.AdminLimitsResponse']
export type EffectiveLimit =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_limits.Effective']
export type DeniedFeature =
  Schemas['github_com_openctemio_openctem_api_internal_app_entitlement.DeniedFeature']
export type SetLimitRequest = Schemas['internal_infra_http_handler.SetLimitRequest']
export type OrganizationLimitsResponse =
  Schemas['internal_infra_http_handler.OrganizationLimitsResponse']
export type OrganizationLimit = Schemas['internal_infra_http_handler.OrganizationLimit']
export type OrganizationDeniedFeature =
  Schemas['internal_infra_http_handler.OrganizationDeniedFeature']
export type AdminTenantModulesResponse =
  Schemas['internal_infra_http_handler.AdminTenantModulesResponse']
export type ModuleEntitlement =
  Schemas['github_com_openctemio_openctem_api_internal_app_entitlement.ModuleEntitlement']
export type SetFeatureDenyRequest = Schemas['internal_infra_http_handler.SetFeatureDenyRequest']
export type DeleteFeatureDenyRequest =
  Schemas['internal_infra_http_handler.DeleteFeatureDenyRequest']
// Admin console: the sign-up policy (System > Sign-up)
export type SignupPolicyResponse = Schemas['internal_infra_http_handler.SignupPolicyResponse']
export type UpdateSignupPolicyRequest =
  Schemas['internal_infra_http_handler.UpdateSignupPolicyRequest']
// Admin console: the platform e-mail settings (System > E-mail, RFC-079)
export type EmailSettingsResponse = Schemas['internal_infra_http_handler.EmailSettingsResponse']
export type UpdateEmailSettingsRequest =
  Schemas['internal_infra_http_handler.UpdateEmailSettingsRequest']
// Admin console: the operator's legal information (System > Legal, RFC-079)
export type LegalSettingsResponse = Schemas['internal_infra_http_handler.LegalSettingsResponse']
export type UpdateLegalSettingsRequest =
  Schemas['internal_infra_http_handler.UpdateLegalSettingsRequest']
export type AuditChainSample =
  Schemas['github_com_openctemio_openctem_api_internal_app_audit_chainclassify.Sample']
export type AuditChainClass =
  Schemas['github_com_openctemio_openctem_api_internal_app_audit_chainclassify.Class']

/** GET /api/v1/easm/summary — the EASM overview (RFC-036). */
export type EASMSummary = Schemas['github_com_openctemio_openctem_api_internal_app_easm.Summary']
export type EASMChangePage =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_easmchange.Page']
export type EASMChange = Schemas['github_com_openctemio_openctem_api_pkg_domain_easmchange.Change']
export type EASMRisk = Schemas['github_com_openctemio_openctem_api_internal_app_easm.Risk']
/** Lookalike-domain monitoring (RFC-083). */
export type LookalikeWatchList = Schemas['internal_infra_http_handler.LookalikeWatchList']
export type LookalikeWatch =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_lookalike.Watch']
export type LookalikeCandidate =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_lookalike.CandidateRecord']
export type LookalikeCandidateList = Schemas['internal_infra_http_handler.LookalikeCandidateList']
/** GET /api/v1/easm/network-seeds (RFC-082). */
export type EASMNetworkSeedList = Schemas['internal_infra_http_handler.EASMNetworkSeedList']
export type EASMNetworkSeed =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.SeedView']
/** GET /api/v1/assets/{id}/web-evidence (RFC-081). */
export type WebEvidenceList = Schemas['internal_infra_http_handler.WebEvidenceListResponse']
export type WebEvidenceItem = Schemas['internal_infra_http_handler.WebEvidenceResponse']

/** A scan run's tasks (RFC-046): GET /api/v1/scan-runs and /scan-runs/{id}. */
export type RunTaskSummary = Schemas['internal_infra_http_handler.RunTaskSummaryResponse']
export type RunTask = Schemas['internal_infra_http_handler.RunTaskResponse']
/** GET /api/v1/scan-runs/{id}/tasks — one cursor page of a run's tasks. */
export type RunTaskPage = Schemas['internal_infra_http_handler.RunTaskPageResponse']
/** GET /api/v1/scan-runs/{id}/tasks/{task_id}/logs — the log lines a task's sensor sent. */
export type RunTaskLogs = Schemas['internal_infra_http_handler.RunTaskLogsResponse']
export type RunTaskLogLine = Schemas['internal_infra_http_handler.RunTaskLogLine']
/** GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement — why a queued task waits. */
export type RunTaskPlacement = Schemas['internal_infra_http_handler.RunTaskPlacementResponse']
/** GET /api/v1/scan-runs/{id}/stages — how each stage of a run was planned. */
export type RunStage = Schemas['internal_infra_http_handler.RunStageResponse']
export type RunStageList = Schemas['internal_infra_http_handler.RunStageListResponse']
/** GET /api/v1/scan-runs/{id}/events — a run timeline (research/62 P0-4). */
export type RunEvent = Schemas['internal_infra_http_handler.RunEvent']
export type RunEventsResponse = Schemas['internal_infra_http_handler.RunEventsResponse']
export type RunMap = Schemas['internal_infra_http_handler.RunMapResponse']
export type RunMapNode = Schemas['internal_infra_http_handler.RunMapNode']
export type RunStepOutputs = Schemas['internal_infra_http_handler.RunStepOutputsResponse']
export type RunStepOutput = Schemas['internal_infra_http_handler.RunStepOutput']
/** GET /api/v1/easm/candidates — the attribution review queue. */
export type EASMReviewPage =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.ReviewPage']
export type EASMReviewItem =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.ReviewItem']
export type EASMVerifiedDomain = Schemas['internal_infra_http_handler.EASMVerifiedDomain']
export type EASMVerifiedDomainList = Schemas['internal_infra_http_handler.EASMVerifiedDomainList']
export type EASMReviewEvidence =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.ReviewEvidence']
/** POST /api/v1/easm/candidates/decisions */
export type EASMDecisionResult =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.DecisionResult']
/** The scope entries a confirmation added (research/117). */
export type EASMConfirmScopeResult =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.ConfirmScopeResult']
/** GET /api/v1/easm/suggestions — the attack surface suggestion cards. */
export type EASMSuggestionCards =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.SuggestionCards']
export type EASMSuggestionCard =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.SuggestionCard']
export type EASMSuggestionAddress =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.SuggestionAddress']
/** GET/POST/PATCH /api/v1/easm/seeds — EASM seeds (RFC-036 §6.3). */
export type EASMSettings = Schemas['internal_infra_http_handler.EASMSettingsResponse']
export type EASMSweepTicket =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.SweepTicket']

// Platform content packs (Console > System > Content packs).
export type PlatformContentPackResponse =
  Schemas['internal_infra_http_handler.PlatformContentPackResponse']
export type PlatformContentPackListResponse =
  Schemas['internal_infra_http_handler.PlatformContentPackListResponse']
export type ContentChannelResponse = Schemas['internal_infra_http_handler.ContentChannelResponse']
export type ContentSigningKeyResponse =
  Schemas['internal_infra_http_handler.ContentSigningKeyResponse']
export type ContentLintReport =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_contentpack.LintReport']
export type ContentLintIssue =
  Schemas['github_com_openctemio_openctem_api_pkg_domain_contentpack.Issue']

// Content catalog (Settings > Content catalog, RFC-099).
export type ContentPackageVersion =
  Schemas['internal_infra_http_handler.ContentPackageVersionResponse']
export type ContentPackageListItem = Schemas['internal_infra_http_handler.ContentPackageListItem']
export type ContentPackageList = Schemas['internal_infra_http_handler.ContentPackageListResponse']
export type ContentPackageDetail =
  Schemas['internal_infra_http_handler.ContentPackageDetailResponse']
export type ContentInstall = Schemas['internal_infra_http_handler.ContentInstallResponse']
export type ContentInstallRequest = Schemas['internal_infra_http_handler.ContentRequestResponse']
export type ContentOutcome = Schemas['internal_infra_http_handler.ContentOutcomeResponse']
export type ContentCatalogSettings = Schemas['internal_infra_http_handler.ContentSettingsResponse']
export type ContentTrust = Schemas['internal_infra_http_handler.ContentTrustResponse']
export type ContentPackagePermissions =
  Schemas['github_com_openctemio_openctem_api_pkg_contentpkg.Permissions']
