/**
 * Retest check hooks: the check someone on the security team attaches to a
 * finding that has no automatic retest, so "Retest now" and the proof of fix
 * can re-run it on a sensor. Design: research/221 (finding retest checks).
 *
 *   GET    /api/v1/findings/{id}/retest-check            — { check } (findings:read)
 *   POST   /api/v1/findings/{id}/retest-check/validate   — dry run, nothing saved
 *   PUT    /api/v1/findings/{id}/retest-check            — attach or replace
 *   DELETE /api/v1/findings/{id}/retest-check            — detach (template stays in the library)
 *   POST   /api/v1/findings/{id}/retest-check/approve    — second-person approval of an intrusive check
 *
 * The writes need findings:retest_checks:write, the approval scope approval
 * rights and a recent sign-in (the shared API client opens the step-up
 * dialog). The API is the only authority: the tenant comes from the token and
 * every route is limited to the finding's data scope. The target is always
 * the finding's own target, so a check carries no target, and credentials
 * (Authorization, Cookie) are refused by the API.
 *
 * The types are local because the generated contract is produced at build
 * time from the API and is not committed.
 */

'use client'

import useSWR, { useSWRConfig } from 'swr'
import useSWRMutation from 'swr/mutation'
import { del, get, post, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

export type RetestCheckKind = 'nuclei' | 'http_assertion'
export type RetestCheckTier = 'T0' | 'T1' | 'T2'
export type HTTPAssertionMethod = 'GET' | 'HEAD' | 'POST' | 'OPTIONS'
export type MatcherPart = 'body' | 'header'

export type HTTPAssertionMatcher =
  | { type: 'status'; status: number[] }
  | {
      type: 'word'
      part: MatcherPart
      words: string[]
      condition?: 'and' | 'or'
      negative?: boolean
    }
  | { type: 'regex'; part: MatcherPart; regex: string[]; negative?: boolean }

export interface HTTPAssertion {
  method: HTTPAssertionMethod
  /** Starts with "/", relative to the finding's target. */
  path: string
  headers?: Record<string, string>
  /** POST only. */
  body?: string
  matchers: HTTPAssertionMatcher[]
  matchers_condition?: 'and' | 'or'
}

export interface RetestCheckPutBody {
  kind: RetestCheckKind
  name?: string
  /** Nuclei YAML (kind nuclei). */
  content?: string
  /** Kind http_assertion. */
  assertion?: HTTPAssertion
  /** Reuse a nuclei template from the organization's library (kind nuclei). */
  template_id?: string
}

export interface RetestCheckValidationError {
  field: string
  message: string
  code: string
}

export interface RetestCheckValidation {
  valid: boolean
  errors: RetestCheckValidationError[]
  tier: RetestCheckTier
  tier_reason: string
  capabilities: string[]
  /** The YAML that would run (generated for an assertion). */
  content: string
  approval_required: boolean
}

export interface RetestCheckApproval {
  required: boolean
  approved: boolean
  approved_by?: string
  approved_at?: string
}

export interface RetestCheck {
  id: string
  finding_id: string
  kind: RetestCheckKind
  template_id: string
  template_name: string
  /** "sha256:…" */
  template_digest: string
  content: string
  assertion: HTTPAssertion | null
  tier: RetestCheckTier
  tier_reason: string
  approval: RetestCheckApproval
  template_pending_sensor_approval: boolean
  calibrated: boolean
  calibrated_at?: string
  created_by?: string
  created_at: string
  updated_by?: string
  updated_at: string
}

export interface RetestCheckResponse {
  check: RetestCheck | null
}

/** Largest nuclei template file read client side (the API enforces its own limit). */
export const MAX_TEMPLATE_FILE_BYTES = 256 * 1024

export function retestCheckEndpoint(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/retest-check`
}

function retestsEndpoint(findingId: string): string {
  return `/api/v1/findings/${findingId}/retests`
}

/** "sha256:abcdef1234567890…" -> "sha256:abcdef123456". */
export function shortDigest(digest: string | undefined | null): string {
  if (!digest) return ''
  const [algo, hex] = digest.includes(':') ? digest.split(':', 2) : ['sha256', digest]
  return `${algo}:${hex.slice(0, 12)}`
}

/** The finding's retest check (null when none is attached). */
export function useFindingRetestCheck(findingId: string | null) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? retestCheckEndpoint(findingId) : null
  return useSWR<RetestCheckResponse>(key, (url: string) => get<RetestCheckResponse>(url), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}

/** Refreshes the check and the retest list (which offers "Retest now" from it). */
function useRefreshCheck(findingId: string) {
  const { mutate } = useSWRConfig()
  return async () => {
    await Promise.all([mutate(retestCheckEndpoint(findingId)), mutate(retestsEndpoint(findingId))])
  }
}

/** Dry run: what would run, its tier and whether it needs approval. Nothing is saved. */
export function useValidateRetestCheck(findingId: string) {
  return useSWRMutation(
    `${retestCheckEndpoint(findingId)}/validate`,
    (url: string, { arg }: { arg: RetestCheckPutBody }) => post<RetestCheckValidation>(url, arg)
  )
}

/** Attach or replace the check. */
export function useSaveRetestCheck(findingId: string) {
  const refresh = useRefreshCheck(findingId)
  return useSWRMutation(
    `${retestCheckEndpoint(findingId)}#put`,
    async (_key: string, { arg }: { arg: RetestCheckPutBody }) => {
      const saved = await put<RetestCheck>(retestCheckEndpoint(findingId), arg)
      await refresh()
      return saved
    }
  )
}

/** Detach the check; its template stays in the organization's template library. */
export function useRemoveRetestCheck(findingId: string) {
  const refresh = useRefreshCheck(findingId)
  return useSWRMutation(`${retestCheckEndpoint(findingId)}#delete`, async () => {
    await del(retestCheckEndpoint(findingId))
    await refresh()
  })
}

/**
 * Approve an intrusive check. The API answers 409 when the approver wrote the
 * current version or no approval is needed, and asks for a recent sign-in
 * (the client opens the step-up dialog and retries once).
 */
export function useApproveRetestCheck(findingId: string) {
  const refresh = useRefreshCheck(findingId)
  return useSWRMutation(`${retestCheckEndpoint(findingId)}/approve`, async (url: string) => {
    const approved = await post<RetestCheck>(url, {})
    await refresh()
    return approved
  })
}
