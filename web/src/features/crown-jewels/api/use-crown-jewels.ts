'use client'

import useSWR from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, patch } from '@/lib/api/client'
import { useRegisterPages } from '@/lib/api/use-register-pages'

// Crown jewels = assets with is_crown_jewel=true
// Uses existing asset API with filter param

/** Page-1 URL of the crown jewel register; also its SWR key. */
export const CROWN_JEWELS_URL = '/api/v1/assets?is_crown_jewel=true&per_page=100'

interface PaginatedAssets {
  data: Record<string, unknown>[]
  total: number
}

export function useCrownJewels() {
  return useRegisterPages<Record<string, unknown>>(CROWN_JEWELS_URL)
}

// `enabled` keeps the picker idle until the designate dialog opens.
export function useAllAssets(search?: string, enabled = true) {
  const params = new URLSearchParams({ per_page: '50', page: '1' })
  if (search) params.set('search', search)
  return useSWR<PaginatedAssets>(enabled ? `/api/v1/assets?${params.toString()}` : null, get, {
    revalidateOnFocus: false,
  })
}

export function useToggleCrownJewel(assetId: string) {
  return useSWRMutation(
    `/api/v1/assets/${assetId}/crown-jewel`,
    (
      url: string,
      {
        arg,
      }: {
        arg: {
          is_crown_jewel: boolean
          business_impact_score: number
          business_impact_notes: string
        }
      }
    ) => patch(url, arg)
  )
}

export function useDesignateCrownJewel() {
  return useSWRMutation(
    'crown-jewel-designate',
    (
      _: string,
      {
        arg,
      }: {
        arg: {
          assetId: string
          businessImpactScore: number
          businessImpactNotes: string
        }
      }
    ) =>
      patch(`/api/v1/assets/${arg.assetId}/crown-jewel`, {
        is_crown_jewel: true,
        business_impact_score: arg.businessImpactScore,
        business_impact_notes: arg.businessImpactNotes,
      })
  )
}

export function useUndesignateCrownJewel() {
  return useSWRMutation(
    'crown-jewel-undesignate',
    (
      _: string,
      {
        arg,
      }: {
        arg: {
          assetId: string
        }
      }
    ) =>
      patch(`/api/v1/assets/${arg.assetId}/crown-jewel`, {
        is_crown_jewel: false,
        business_impact_score: 0,
        business_impact_notes: '',
      })
  )
}
