/**
 * Whether a new scan may be saved to start when its scope is approved
 * (RFC-054 §12.8): the scope check refused some targets, and every refused
 * one only waits for a pending scope entry. The server decides again on
 * create; this only offers the button.
 */

import type { ApiScopeCheckResult } from '@/features/scope'

export function onlyAwaitingApproval(results: ApiScopeCheckResult[] | undefined): boolean {
  const refused = (results ?? []).filter((r) => !r.allowed)
  return refused.length > 0 && refused.every((r) => r.code === 'entry_pending')
}
