/**
 * Finding API Hooks
 *
 * SWR hooks for fetching and mutating finding data from backend
 *
 * Tenant is now determined from JWT token (token-based tenant)
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, patch, put } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import type {
  ApiFinding,
  ApiFindingListResponse,
  ApiFindingComment,
  FindingApiFilters,
  CreateFindingInput,
  UpdateFindingStatusInput,
  UpdateFindingSeverityInput,
  AssignFindingInput,
  AddCommentInput,
} from './finding-api.types'
import type { ApiApproval, ApprovalStatus } from '../types/finding.types'
import type { ApprovalEvaluation, ApprovalPolicy } from '../lib/approval-policy'

// ============================================
// SWR CONFIGURATION
// ============================================

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  // Don't retry on client errors (4xx) - only retry on server/network errors
  shouldRetryOnError: (error) => {
    // Don't retry on 4xx errors (client errors like 403, 404, etc.)
    if (error?.statusCode >= 400 && error?.statusCode < 500) {
      return false
    }
    // Retry on 5xx or network errors
    return true
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 2000,
  onError: (error) => {
    handleApiError(error, {
      showToast: true,
      logError: true,
    })
  },
}

// ============================================
// ENDPOINT BUILDERS
// ============================================

export function buildFindingsEndpoint(filters?: FindingApiFilters): string {
  const baseUrl = '/api/v1/findings'
  if (!filters) return baseUrl
  const queryString = buildFindingsQuery(filters).toString()
  return queryString ? `${baseUrl}?${queryString}` : baseUrl
}

/** The list query (RFC-048 param names) for a filter set; shared by list, stats and export. */
export function buildFindingsQuery(filters: FindingApiFilters): URLSearchParams {
  const params = new URLSearchParams()

  // The list query contract's param names (RFC-048): the singular response
  // field names. The old plural names still work on the server, as
  // deprecated aliases.
  if (filters.asset_id) params.set('asset_id', filters.asset_id)
  if (filters.branch_id) params.set('branch_id', filters.branch_id)
  if (filters.branch_id && filters.branch_status && filters.branch_status !== 'all')
    params.set('branch_status', filters.branch_status)
  if (filters.component_id) params.set('component_id', filters.component_id)
  if (filters.vulnerability_id) params.set('vulnerability_id', filters.vulnerability_id)
  if (filters.tool_name) params.set('tool_name', filters.tool_name)
  if (filters.rule_id) params.set('rule_id', filters.rule_id)
  if (filters.scan_id) params.set('scan_id', filters.scan_id)
  if (filters.file_path) params.set('file_path', filters.file_path)
  if (filters.search) params.set('q', filters.search)
  if (filters.page) params.set('page', String(filters.page))
  if (filters.per_page) params.set('per_page', String(filters.per_page))

  if (filters.severities?.length) params.set('severity', filters.severities.join(','))
  if (filters.statuses?.length) params.set('status', filters.statuses.join(','))
  if (filters.exclude_statuses?.length) params.set('status_not', filters.exclude_statuses.join(','))
  if (filters.sources?.length) params.set('source', filters.sources.join(','))

  // CTEM prioritization filters (RFC-017)
  if (filters.priority_classes?.length)
    params.set('priority_class', filters.priority_classes.join(','))
  if (filters.is_in_kev) params.set('is_in_kev', 'true')
  if (filters.is_reachable) params.set('is_reachable', 'true')
  if (filters.branch_only) params.set('branch_only', 'true')
  if (filters.assigned_to_me) params.set('related_to', 'me')
  if (filters.sla_statuses?.length) params.set('sla_status', filters.sla_statuses.join(','))
  if (filters.epss_min != null) params.set('epss_score_gte', String(filters.epss_min))
  if (filters.finding_ids?.length) params.set('id', filters.finding_ids.join(','))
  if (filters.cve_ids?.length) params.set('cve_id', filters.cve_ids.join(','))
  if (filters.finding_types?.length) params.set('finding_type', filters.finding_types.join(','))
  if (filters.families?.length) params.set('family', filters.families.join(','))
  if (filters.state) params.set('state', filters.state)
  if (filters.asset_owner_id) params.set('asset_owner_id', filters.asset_owner_id)
  if (filters.asset_owner_unassigned) params.set('asset_owner_id_null', 'true')
  if (filters.view) params.set('view', filters.view)
  if (filters.sort) params.set('sort', filters.sort)
  return params
}

function buildFindingEndpoint(findingId: string): string {
  return `/api/v1/findings/${findingId}`
}

/** The SWR key of one finding's detail (useFindingApi). */
export const findingDetailKey = buildFindingEndpoint

function buildAssetFindingsEndpoint(
  assetId: string,
  sort?: string,
  page?: number,
  perPage?: number
): string {
  const baseUrl = `/api/v1/assets/${assetId}/findings`
  const params = new URLSearchParams()

  if (sort) params.set('sort', sort)
  if (page) params.set('page', String(page))
  if (perPage) params.set('per_page', String(perPage))

  const queryString = params.toString()
  return queryString ? `${baseUrl}?${queryString}` : baseUrl
}

// ============================================
// FETCHER FUNCTIONS
// ============================================

export async function fetchFindings(url: string): Promise<ApiFindingListResponse> {
  return get<ApiFindingListResponse>(url)
}

async function fetchFinding(url: string): Promise<ApiFinding> {
  return get<ApiFinding>(url)
}

// ============================================
// FINDING HOOKS
// ============================================

/**
 * Fetch findings list for current tenant
 *
 * @example
 * ```typescript
 * function FindingList() {
 *   const { data, error, isLoading } = useFindingsApi({ page: 1, severities: ['critical', 'high'] })
 *
 *   if (isLoading) return <Loading />
 *   if (error) return <Error error={error} />
 *
 *   return (
 *     <ul>
 *       {data?.data.map(finding => (
 *         <li key={finding.id}>{finding.message}</li>
 *       ))}
 *     </ul>
 *   )
 * }
 * ```
 */
export function useFindingsApi(
  filters?: FindingApiFilters,
  config?: SWRConfiguration & {
    /** false = do not fetch yet (e.g. the list is only shown inside a closed dialog) */
    enabled?: boolean
  }
) {
  const { currentTenant } = useTenant()
  const { enabled = true, ...swrConfig } = config ?? {}

  // Ensure user has a tenant before making requests
  const key = currentTenant && enabled ? buildFindingsEndpoint(filters) : null

  return useSWR<ApiFindingListResponse>(key, fetchFindings, { ...defaultConfig, ...swrConfig })
}

/**
 * Fetch a single finding by ID
 */
export function useFindingApi(findingId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  // Ensure user has a tenant before making requests
  const key = currentTenant && findingId ? buildFindingEndpoint(findingId) : null

  return useSWR<ApiFinding>(key, fetchFinding, { ...defaultConfig, ...config })
}

/**
 * Fetch findings for a specific asset
 */
export function useAssetFindingsApi(
  assetId: string | null,
  sort?: string,
  page?: number,
  perPage?: number,
  config?: SWRConfiguration
) {
  const { currentTenant } = useTenant()

  // Ensure user has a tenant before making requests
  const key =
    currentTenant && assetId ? buildAssetFindingsEndpoint(assetId, sort, page, perPage) : null

  return useSWR<ApiFindingListResponse>(key, fetchFindings, { ...defaultConfig, ...config })
}

// ============================================
// MUTATION HOOKS
// ============================================

/**
 * Create a new finding
 */
export function useCreateFindingApi() {
  const { currentTenant } = useTenant()

  // Ensure user has a tenant before making requests
  return useSWRMutation(
    currentTenant ? '/api/v1/findings' : null,
    async (url: string, { arg }: { arg: CreateFindingInput }) => {
      return post<ApiFinding>(url, arg)
    }
  )
}

/**
 * Update finding status
 */
export function useUpdateFindingStatusApi(findingId: string) {
  const { currentTenant } = useTenant()

  // Ensure user has a tenant before making requests
  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/status` : null,
    async (url: string, { arg }: { arg: UpdateFindingStatusInput }) => {
      return patch<ApiFinding>(url, arg)
    }
  )
}

/**
 * Mark a finding as a duplicate of another (RFC-043): findingId is folded
 * into the original (POST /findings/{original}/duplicates), which keeps the
 * stronger status and inherits its comments, retests, evidence and tickets.
 * Returns the original finding.
 */
export function useMarkDuplicateApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `mark-duplicate:${findingId}` : null,
    async (_key: string, { arg }: { arg: { duplicate_of_id: string } }) => {
      return post<ApiFinding>(
        `${buildFindingEndpoint(encodeURIComponent(arg.duplicate_of_id))}/duplicates`,
        {
          finding_id: findingId,
        }
      )
    }
  )
}

/**
 * Change a finding's severity (an analyst override with a reason, or a
 * restore of the reported severity). The answer is the finding with its
 * recomputed priority, SLA deadline and reason; a downgrade that waits for
 * approval comes back unchanged with `pending_severity_request` set.
 */
export function useUpdateFindingSeverityApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/severity` : null,
    async (url: string, { arg }: { arg: UpdateFindingSeverityInput }) => {
      return patch<ApiFinding>(url, arg)
    }
  )
}

export type SeverityRequestDecision = 'approve' | 'reject' | 'cancel'

/**
 * Decide a pending severity request: approve or reject it (findings:approve)
 * or withdraw one's own (cancel). Answers the finding as it is now.
 */
export async function decideSeverityRequest(
  findingId: string,
  requestId: string,
  decision: SeverityRequestDecision,
  reason?: string
): Promise<ApiFinding> {
  const url = `${buildFindingEndpoint(findingId)}/severity-requests/${encodeURIComponent(requestId)}/${decision}`
  return post<ApiFinding>(url, decision === 'reject' ? { reason } : {})
}

/**
 * Assign finding to a user
 */
export function useAssignFindingApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/assign` : null,
    async (url: string, { arg }: { arg: AssignFindingInput }) => {
      return post<ApiFinding>(url, arg)
    }
  )
}

/**
 * Unassign finding from current assignee
 */
export function useUnassignFindingApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/unassign` : null,
    async (url: string) => {
      return post<ApiFinding>(url, {})
    }
  )
}

// ============================================
// VALIDATION (CTEM Stage-4)
// ============================================

/** Result of requesting a validation (safe-check) run for a finding. */
export interface RequestValidationResult {
  finding_id: string
  command_id: string
  status: string
}

/**
 * Request a CTEM Stage-4 validation run for a finding (RFC-011).
 * POST /api/v1/findings/{id}/validate — dispatches a safe-check job to a sensor;
 * the outcome is applied to the finding asynchronously when the sensor reports back.
 */
export function useRequestValidationApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/validate` : null,
    async (url: string) => {
      return post<RequestValidationResult>(url, {})
    }
  )
}

/**
 * True when an error returned by {@link useRequestValidationApi} indicates that
 * no validation-capable sensor is currently online for the tenant. The API
 * signals this as a 400 wrapping `ErrNoValidationSensor` whose message contains
 * "no validation-capable sensor is online". Callers surface a deploy-a-sensor
 * hint instead of a generic failure toast.
 */
export function isNoValidationSensorError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : typeof error === 'string' ? error : ''
  return /no validation-capable sensor/i.test(message)
}

/** A single validation-evidence record recorded against a finding. */
export interface ValidationEvidenceItem {
  id: string
  finding_id: string
  executor_kind: string
  technique: string
  outcome: string
  summary: string
  created_at: string
  started_at?: string
  ended_at?: string
  // Detection correlation verdict — answers "did any control OBSERVE this
  // validation?", a different question from `outcome` ("is the exposure still
  // reachable?"). See api internal/app/validation/detection.go. Values:
  // observed | not_observed | no_telemetry_source | not_applicable |
  // not_evaluated. `detection_is_gap` is the precomputed safe predicate
  // (true only for not_observed) so the UI never gets the comparison wrong.
  // Both optional so the panel degrades gracefully against an older API.
  detection_status?: string
  detection_is_gap?: boolean
}

interface ValidationEvidenceResponse {
  evidence: ValidationEvidenceItem[]
}

/**
 * Fetch the validation evidence recorded for a finding.
 * GET /api/v1/findings/{id}/evidence
 */
export function useFindingValidationEvidenceApi(
  findingId: string | null,
  config?: SWRConfiguration
) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/evidence` : null

  return useSWR<ValidationEvidenceResponse>(
    key,
    (url: string) => get<ValidationEvidenceResponse>(url),
    { ...defaultConfig, ...config }
  )
}

/**
 * Input for creating an external ticket from a finding. `project_key` is
 * optional — when omitted the backend routes to the tenant's configured default
 * project / routing rules. `provider` defaults to "jira" server-side.
 */
export interface CreateFindingTicketInput {
  provider?: string
  project_key?: string
  issue_type?: string
}

/** Response from creating a ticket from a finding. */
export interface FindingTicketInfo {
  finding_id: string
  ticket_key: string
  ticket_url: string
  linked_at: string
}

/**
 * Create (and link) an external ticket from a finding.
 * POST /api/v1/findings/{id}/create-ticket
 */
export function useCreateFindingTicketApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/create-ticket` : null,
    async (url: string, { arg }: { arg: CreateFindingTicketInput }) => {
      return post<FindingTicketInfo>(url, arg)
    }
  )
}

// ============================================
// COMMENT HOOKS
// ============================================

/**
 * Add comment to a finding
 */
export function useAddFindingCommentApi(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && findingId ? `${buildFindingEndpoint(findingId)}/comments` : null,
    async (url: string, { arg }: { arg: AddCommentInput }) => {
      return post<ApiFindingComment>(url, arg)
    }
  )
}

// ============================================
// FINDING STATS HOOKS
// ============================================

import type { FindingStatsResponse } from './finding-api.types'

export async function fetchFindingStats(url: string): Promise<FindingStatsResponse> {
  return get<FindingStatsResponse>(url)
}

/**
 * Filters supported by the /findings/stats endpoint.
 *
 * The backend currently supports:
 *  - assetId: scope the counts to a single asset (used by the
 *    /findings page when filtered by `?assetId=…` so the severity
 *    cards reflect the filtered table, not the global tenant counts).
 *  - sources: scope every count to these finding sources (used by the
 *    Exposures type pages, which each show one type of finding). An older
 *    API ignores the param and answers tenant-wide; see
 *    `useFindingTypeStats` for how that is detected.
 *
 * Add new filters here as the backend grows.
 */
export interface FindingStatsFilters extends Omit<FindingApiFilters, 'page' | 'per_page' | 'sort'> {
  assetId?: string | null
}

/**
 * `/api/v1/findings/stats` with the given filters as query params. Stats take
 * every list filter (RFC-048), so the numbers match the table they sit over.
 */
export function buildFindingStatsUrl(filters?: FindingStatsFilters): string {
  if (!filters) return '/api/v1/findings/stats'
  const { assetId, ...rest } = filters
  const params = buildFindingsQuery({ ...rest, asset_id: rest.asset_id ?? assetId ?? undefined })
  const queryString = params.toString()
  return queryString ? `/api/v1/findings/stats?${queryString}` : '/api/v1/findings/stats'
}

/** `/api/v1/findings/export` for a filter set (RFC-048; needs findings:export). */
export function buildFindingsExportUrl(
  filters: FindingApiFilters,
  format: 'csv' | 'ndjson'
): string {
  const { page: _page, per_page: _perPage, sort: _sort, ...rest } = filters
  const params = buildFindingsQuery(rest)
  params.set('format', format)
  return `/api/v1/findings/export?${params.toString()}`
}

/**
 * Fetch finding stats (total, by severity, by status, by source)
 *
 * Pass filters to scope the stats. Without filters this returns
 * tenant-wide counts. The cache key includes the serialized filters
 * so different filter combinations don't trample each other in SWR.
 */
export function useFindingStatsApi(
  filters?: FindingStatsFilters,
  config?: SWRConfiguration & {
    /** false = do not fetch yet (e.g. while the page's URL params are not final) */
    enabled?: boolean
  }
) {
  const { currentTenant } = useTenant()
  const { enabled = true, ...swrConfig } = config ?? {}

  const url = buildFindingStatsUrl(filters)

  const key = currentTenant && enabled ? url : null

  return useSWR<FindingStatsResponse>(key, fetchFindingStats, { ...defaultConfig, ...swrConfig })
}

// ============================================
// CACHE UTILITIES
// ============================================

/**
 * Invalidate findings cache
 */
export async function invalidateFindingsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/findings'), undefined, {
    revalidate: true,
  })
}

// ============================================
// APPROVAL HOOKS
// ============================================

/**
 * Request approval for a finding status change
 */
export function useRequestApproval(findingId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `/api/v1/findings/${findingId}/approvals` : null,
    async (
      url: string,
      {
        arg,
      }: {
        arg: {
          requested_status: string
          justification: string
          closure_reason: string
          expires_at?: string
        }
      }
    ) => {
      // Usually a pending request; an approved one (single_person) when the
      // organization lets the requester decide this false positive alone.
      const response = await post<ApiApproval>(url, arg)
      return response
    }
  )
}

/** How a request of one status on one finding is decided now. */
export interface FalsePositivePolicy {
  fp_approval: FPApprovalLevel
  /** One person holding findings:approve may decide it alone. */
  single_person: boolean
  /** ...and the caller is such a person: it applies at once. */
  can_decide_alone: boolean
  /** The finding is material (always four-eyes under high_and_above). */
  material: boolean
  pending_fp_approval?: FPApprovalLevel
  pending_fp_approval_at?: string
  /** The approval policy's evaluation: tier, why, who may approve, how long. */
  evaluation?: ApprovalEvaluation
}

/**
 * GET /api/v1/findings/{id}/approvals/policy?status=, only while `enabled`:
 * how a request for `status` (false_positive or accepted) would be decided.
 */
export function useFindingApprovalPolicy(
  findingId: string,
  status: 'false_positive' | 'accepted',
  enabled: boolean
) {
  const { currentTenant } = useTenant()
  return useSWR<FalsePositivePolicy>(
    currentTenant && enabled && findingId
      ? `/api/v1/findings/${encodeURIComponent(findingId)}/approvals/policy?status=${status}`
      : null,
    get,
    defaultConfig
  )
}

/**
 * Approve a pending approval
 */
export function useApproveStatus(approvalId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `/api/v1/approvals/${approvalId}/approve` : null,
    async (url: string) => {
      // 200 with status "pending" while more sign-offs are needed.
      return post<ApiApproval>(url, {})
    }
  )
}

/**
 * Reject a pending approval
 */
export function useRejectApproval(approvalId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `/api/v1/approvals/${approvalId}/reject` : null,
    async (url: string, { arg }: { arg: { reason: string } }) => {
      const response = await post(url, arg)
      return response
    }
  )
}

/** One page of approvals and the count of every status (GET /api/v1/approvals). */
export interface ApprovalListResponse {
  data: ApiApproval[]
  total: number
  page: number
  per_page: number
  /** Count per status under the caller's data scope, zero included. */
  status_counts: Record<ApprovalStatus, number>
  /**
   * The viewer is the organization's only active person and its owner: they
   * may approve their own pending requests with an authenticator code.
   */
  self_approval_available?: boolean
}

/** The approved request after a sole member's own approval. */
export interface SelfApproveResponse extends ApiApproval {
  /** The acceptance end asked for was brought forward to the self-approval limit. */
  end_shortened: boolean
}

/**
 * The sole member of the organization approves their own pending request
 * (POST /api/v1/approvals/{id}/self-approve) with a reason and a fresh code
 * from their authenticator app. The server decides whether it is allowed.
 */
export function selfApproveFindingApproval(id: string, input: { reason: string; code: string }) {
  return post<SelfApproveResponse>(
    `/api/v1/approvals/${encodeURIComponent(id)}/self-approve`,
    input
  )
}

/** The organization's finding approval settings. */
/** Who decides a false positive (accepted risk always needs a second person). */
export type FPApprovalLevel = 'all' | 'high_and_above' | 'off'

export interface FindingApprovalSettings {
  /** Emailed when the sole member approves their own request. */
  backup_contact_email: string
  /** The false-positive approval level in force. */
  fp_approval?: FPApprovalLevel
  /** A lower level chosen less than 24 hours ago, in force at pending_fp_approval_at. */
  pending_fp_approval?: FPApprovalLevel
  pending_fp_approval_at?: string
  /** Share (0-10 %) of single-person false positives flagged for a second look. */
  second_look_percent?: number
  /** A lower share chosen less than 24 hours ago, in force at pending_second_look_at. */
  pending_second_look_percent?: number
  pending_second_look_at?: string
  /** The approval policy in force. */
  policy?: ApprovalPolicy
  /** A relaxing policy chosen less than 24 hours ago, in force at pending_policy_at. */
  pending_policy?: ApprovalPolicy
  pending_policy_at?: string
  /** The platform's lowest tier per "<kind>.<class>". */
  floors?: Record<string, string>
  /** The platform's default tier per "<kind>.<class>". */
  defaults?: Record<string, string>
}

/**
 * PUT body: any of the plain fields, or the whole approval policy.
 * `cancel_pending` drops every waiting lowering (level, second-look share,
 * relaxing policy) and keeps the values in force.
 */
export type FindingApprovalSettingsUpdate = Partial<
  Pick<FindingApprovalSettings, 'backup_contact_email' | 'fp_approval' | 'second_look_percent'>
> & { policy?: ApprovalPolicy; cancel_pending?: boolean }

const FINDING_APPROVAL_SETTINGS_URL = '/api/v1/organization/settings/finding-approvals'

/** Read the organization's finding approval settings. */
export function useFindingApprovalSettings() {
  const { currentTenant } = useTenant()
  return useSWR<FindingApprovalSettings>(
    currentTenant ? FINDING_APPROVAL_SETTINGS_URL : null,
    get,
    defaultConfig
  )
}

/**
 * Save the organization's finding approval settings (settings:write and a
 * recent sign-in; the API client asks for re-authentication when needed).
 * Fields left out keep their value.
 */
export function updateFindingApprovalSettings(input: FindingApprovalSettingsUpdate) {
  return put<FindingApprovalSettings>(FINDING_APPROVAL_SETTINGS_URL, input)
}

/**
 * List the tenant's approvals, one server page at a time, filtered by status
 * (omit for every status). The server applies the caller's data scope to the
 * page, the total and the status counts.
 */
export function useApprovals(page = 1, perPage = 20, status?: ApprovalStatus) {
  const { currentTenant } = useTenant()
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  if (status) params.set('status', status)
  return useSWR<ApprovalListResponse>(currentTenant ? `/api/v1/approvals?${params}` : null, get, {
    ...defaultConfig,
    refreshInterval: 30000,
    keepPreviousData: true,
  })
}

/**
 * List approvals for a specific finding
 */
export function useFindingApprovals(findingId: string | undefined) {
  const { currentTenant } = useTenant()
  return useSWR<ApiApproval[]>(
    currentTenant && findingId ? `/api/v1/findings/${findingId}/approvals` : null,
    get,
    defaultConfig
  )
}

/**
 * Cancel own approval request
 */
/**
 * Remind the eligible approvers of the caller's own pending request (the API
 * allows one reminder per request per hour; a second answers 409 CONFLICT).
 */
export function remindApprovers(approvalId: string): Promise<{ reminded: number }> {
  return post<{ reminded: number }>(`/api/v1/approvals/${approvalId}/remind`, {})
}

export function useCancelApproval(approvalId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `/api/v1/approvals/${approvalId}/cancel` : null,
    async (url: string) => {
      return post(url, {})
    }
  )
}
