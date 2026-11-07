import { del, post } from '@/lib/api/client'
import type {
  EASMAddressAddResult,
  EASMAddressRejectResult,
  EASMLookupRetryResult,
  EASMNetworkAnswerResult,
} from '@/lib/api/generated'

/**
 * Bulk decisions on the addresses card (research/425). The server checks
 * every address and range against the caller's own card; nothing posted is
 * trusted. Adding goes through the scope service (step-up and approvals are
 * handled by the shared client and the server).
 */
const BASE = '/api/v1/easm/suggestions'

/** What a person chose on the card: addresses, whole groups (their keys), or
 * every waiting address, also past the card's list. */
export interface CardSelection {
  addresses: string[]
  groups: string[]
  allWaiting: boolean
}

function selectionBody(sel: CardSelection) {
  return { addresses: sel.addresses, groups: sel.groups, all_waiting: sel.allWaiting }
}

/** Adds the selection; chosen addresses next to each other become ranges
 * that hold only them. Third-party addresses go only with includeShared. */
export function addCardAddresses(sel: CardSelection, ranges: string[] = [], includeShared = false) {
  return post<EASMAddressAddResult>(`${BASE}/addresses/add`, {
    ...selectionBody(sel),
    ranges,
    include_shared: includeShared,
  })
}

export function rejectCardAddresses(sel: CardSelection) {
  return post<EASMAddressRejectResult>(`${BASE}/addresses/reject`, selectionBody(sel))
}

/** Asks the sensors again for the network of addresses whose lookup failed. */
export function retryAddressLookup(sel: CardSelection) {
  return post<EASMLookupRetryResult>(`${BASE}/addresses/lookup`, selectionBody(sel))
}

export function answerNetwork(key: string, ours: boolean) {
  return post<EASMNetworkAnswerResult>(`${BASE}/networks/${ours ? 'ours' : 'not-ours'}`, { key })
}

export function undoDeclinedNetwork(id: string) {
  return del<void>(`${BASE}/declined-networks/${encodeURIComponent(id)}`)
}

export function removeNetworkSeed(id: string) {
  return del<void>(`/api/v1/easm/network-seeds/${encodeURIComponent(id)}`)
}

/** Removes the scope entries a decision just added (the Undo). */
export function removeScopeEntries(ids: string[]) {
  return post<unknown>('/api/v1/scope/targets/bulk/delete', { target_ids: ids })
}
