/**
 * How a finding can be verified (GET /api/v1/findings/{id}/verification) and
 * its verification checklist (GET/PUT /api/v1/verification-checklists/{id}).
 * The server decides both; the console renders them.
 */

import useSWR, { type SWRConfiguration } from 'swr'
import { get, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

export type VerificationMethodKind =
  'retest' | 'covered_scan' | 'safe_check' | 'rotation_proof' | 'evidence_review'

export interface VerificationMethod {
  kind: VerificationMethodKind
  available: boolean
  recommended?: boolean
  counts_as_proof: boolean
  automatic?: boolean
  /** Stable code for why the method is not available. */
  reason?: string
}

export interface VerificationPlan {
  finding_id: string
  status: string
  tier: 'critical' | 'high' | 'standard'
  requirement: 'second_person_or_retest' | 'checklist_or_retest' | 'note'
  second_person_required: boolean
  proof_present: boolean
  external_workflow?: string
  methods: VerificationMethod[]
  evidence: {
    retest?: { outcome: string; completed_at?: string; fresh: boolean }
    checklist: {
      state: 'none' | 'in_progress' | 'complete'
      incomplete?: string[]
      completed_by?: string
      completed_at?: string
      fresh: boolean
      completed_by_caller?: boolean
    }
  }
}

export function findingVerificationKey(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/verification`
}

/** The verification plan of one finding; a null id disables the request. */
export function useFindingVerificationPlan(findingId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? findingVerificationKey(findingId) : null
  return useSWR<VerificationPlan>(key, (url: string) => get<VerificationPlan>(url), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
    ...config,
  })
}

/** The method of a kind in a plan, if listed. */
export function planMethod(
  plan: VerificationPlan | undefined,
  kind: VerificationMethodKind
): VerificationMethod | undefined {
  return plan?.methods.find((m) => m.kind === kind)
}

export interface VerificationChecklist {
  id: string
  finding_id: string
  exposure_cleared: boolean
  evidence_attached: boolean
  register_updated: boolean
  notes: string
  is_complete: boolean
  completed_by?: string
  completed_at?: string
}

export interface VerificationChecklistUpdate {
  exposure_cleared?: boolean
  evidence_attached?: boolean
  register_updated?: boolean
  notes?: string
}

export function verificationChecklistKey(findingId: string): string {
  return `/api/v1/verification-checklists/${encodeURIComponent(findingId)}`
}

/** The finding's checklist; null id disables the request. */
export function useVerificationChecklist(findingId: string | null) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? verificationChecklistKey(findingId) : null
  return useSWR<VerificationChecklist>(key, (url: string) => get<VerificationChecklist>(url), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}

/** Saves checklist items; the server records who completed it. */
export function saveVerificationChecklist(
  findingId: string,
  update: VerificationChecklistUpdate
): Promise<VerificationChecklist> {
  return put<VerificationChecklist>(verificationChecklistKey(findingId), update)
}
