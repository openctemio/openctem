/**
 * Finding evidence hooks (docs/architecture/finding-evidence.md in the API).
 *
 *   GET  /api/v1/findings/{id}/evidence-items[?retest_id=]   masked items, newest first
 *   POST /api/v1/findings/{id}/evidence-items/{item}/reveal  plaintext of placeholders
 *
 * Items are untrusted tool output, masked server-side: secret values are
 * «secret:kind#n» placeholders. A reveal needs findings:evidence:reveal and a
 * recent sign-in (the API client runs the step-up dialog on STEP_UP_REQUIRED
 * and retries once); it is audited server-side. Revealed values are never put
 * in an SWR cache: the caller keeps them in component state for
 * mask_after_seconds and drops them.
 */

'use client'

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  FindingEvidenceItemListResponse,
  FindingEvidenceItemResponse,
  RevealEvidenceResponse,
} from '@/lib/api/generated'

export type FindingEvidenceItem = FindingEvidenceItemResponse

export type RevealPurpose = 'view' | 'copy' | 'copy_curl'

export function evidenceItemsEndpoint(findingId: string, retestId?: string): string {
  const base = `/api/v1/findings/${encodeURIComponent(findingId)}/evidence-items`
  return retestId ? `${base}?retest_id=${encodeURIComponent(retestId)}` : base
}

/** A finding's evidence (or one retest attempt's), newest first. */
export function useFindingEvidenceItems(findingId: string | null, retestId?: string) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? evidenceItemsEndpoint(findingId, retestId) : null
  return useSWR<FindingEvidenceItemListResponse>(
    key,
    (url: string) => get<FindingEvidenceItemListResponse>(url),
    {
      revalidateOnFocus: false,
    }
  )
}

/** Reveal placeholders of one item. Not cached anywhere. */
export async function revealEvidence(
  findingId: string,
  itemId: string,
  placeholders: string[],
  purpose: RevealPurpose
): Promise<Record<string, string>> {
  const res = await post<RevealEvidenceResponse>(
    `/api/v1/findings/${encodeURIComponent(findingId)}/evidence-items/${encodeURIComponent(itemId)}/reveal`,
    { placeholders, purpose }
  )
  return res?.values ?? {}
}
