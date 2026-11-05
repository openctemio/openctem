import { del, post } from '@/lib/api/client'
import type {
  EASMAddressAddResult,
  EASMAddressRejectResult,
  EASMNetworkAnswerResult,
} from '@/lib/api/generated'

/**
 * Bulk decisions on the addresses card (research/425). The server checks
 * every address and range against the caller's own card; nothing posted is
 * trusted. Adding goes through the scope service (step-up and approvals are
 * handled by the shared client and the server).
 */
const BASE = '/api/v1/easm/suggestions'

/** Most items one decision takes (the server's limit). */
export const MAX_DECISION_ITEMS = 200

export function addCardAddresses(
  addresses: string[],
  ranges: string[] = [],
  includeShared = false
) {
  return post<EASMAddressAddResult>(`${BASE}/addresses/add`, {
    addresses,
    ranges,
    include_shared: includeShared,
  })
}

export function rejectCardAddresses(addresses: string[]) {
  return post<EASMAddressRejectResult>(`${BASE}/addresses/reject`, { addresses })
}

export function answerNetwork(key: string, ours: boolean) {
  return post<EASMNetworkAnswerResult>(`${BASE}/networks/${ours ? 'ours' : 'not-ours'}`, { key })
}

export function undoDeclinedNetwork(id: string) {
  return del<void>(`${BASE}/networks/declined/${encodeURIComponent(id)}`)
}

export function removeNetworkSeed(id: string) {
  return del<void>(`/api/v1/easm/network-seeds/${encodeURIComponent(id)}`)
}

/** Removes the scope entries a decision just added (the Undo). */
export function removeScopeEntries(ids: string[]) {
  return post<unknown>('/api/v1/scope/targets/bulk/delete', { target_ids: ids })
}
