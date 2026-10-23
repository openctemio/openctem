'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { SWR_REFERENCE } from '@/lib/swr-config'
import type { FieldContract, FilterContract, FilterContractResponse } from './model'

export const FILTER_CONTRACT_URL = '/api/v1/meta/filters/findings'

/**
 * The filter contract of the findings list, with the fields the caller may
 * use (the server leaves out the rest). Fetched only when something needs it:
 * the Add filter picker opening, or a URL that holds filters the page does
 * not draw itself. A plain load of the list never asks.
 */
export function useFindingFilterContract(enabled: boolean) {
  const { currentTenant } = useTenant()
  const key = enabled && currentTenant?.id ? FILTER_CONTRACT_URL : null
  const { data, error, isLoading } = useSWR<FilterContractResponse>(
    key,
    (url: string) => get<FilterContractResponse>(url),
    { ...SWR_REFERENCE, onError: () => {} }
  )
  return { contract: data?.contract, error, isLoading }
}

/**
 * The params the page draws and sends itself (facet panel, search, sort...).
 * They never need the contract, so a list that uses only these loads with no
 * extra request. Everything else in the URL is a filter the contract names.
 */
export const OWNED_FILTER_PARAMS: ReadonlySet<string> = new Set([
  'severity',
  'status',
  'source',
  'priority_class',
  'sla_status',
  'is_in_kev',
  'is_reachable',
  'branch_only',
  'related_to',
  'pending_approval',
  'acceptance_expires_at_lte',
])

/** Params the context chips draw (an asset, a scan, a CVE group's "View"...). */
export const CONTEXT_FILTER_PARAMS: ReadonlySet<string> = new Set([
  'asset_id',
  'scan_id',
  'cve_id',
  'rule_id',
  'family',
  'finding_type',
  'component_id',
  'asset_owner_id',
  'asset_owner_id_null',
  'asset_group_id',
  'asset_crown_jewel',
])

const IN_OPS = ['in', 'not_in'] as const
const RANGE_OPS = ['gte', 'gt', 'lte', 'lt'] as const

/**
 * What the page-owned fields mean, for drawing their chips before (or
 * without) the contract. The contract, once loaded, wins for any field it has.
 */
export const OWNED_FIELDS: FieldContract[] = [
  { name: 'severity', type: 'enum', ops: [...IN_OPS] },
  { name: 'status', type: 'enum', ops: [...IN_OPS] },
  { name: 'source', type: 'enum', ops: [...IN_OPS] },
  { name: 'priority_class', type: 'enum', ops: [...IN_OPS] },
  { name: 'sla_status', type: 'enum', ops: [...IN_OPS] },
  { name: 'is_in_kev', type: 'boolean', ops: ['eq'] },
  { name: 'is_reachable', type: 'boolean', ops: ['eq'] },
  { name: 'branch_only', type: 'boolean', ops: ['eq'] },
  { name: 'related_to', type: 'enum', ops: ['eq'], enum: ['me'] },
  { name: 'pending_approval', type: 'boolean', ops: ['eq'] },
  { name: 'acceptance_expires_at', type: 'date-time', ops: [...RANGE_OPS] },
]

/** The contract to read chips with: the loaded one, plus the owned fields it lacks. */
export function withOwnedFields(contract: FilterContract | undefined): FilterContract {
  const have = new Set(contract?.fields.map((f) => f.name))
  return {
    ...contract,
    fields: [...(contract?.fields ?? []), ...OWNED_FIELDS.filter((f) => !have.has(f.name))],
  }
}
