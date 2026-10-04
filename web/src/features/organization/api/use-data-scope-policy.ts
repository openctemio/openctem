/**
 * What members who are in no team see in the organization ("everything" or
 * "nothing"). Owners and admins only: the API refuses everyone else, so the
 * hooks do not fetch for them.
 */

import useSWR from 'swr'
import useSWRMutation from 'swr/mutation'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { usePermissions } from '@/lib/permissions'
import type {
  DataScopeImpact,
  DataScopePolicy,
  MembersWithoutGroupSee,
} from '../types/settings.types'

export function useDataScopePolicy(tenantIdOrSlug: string | undefined) {
  const { isAdmin } = usePermissions()
  const key = tenantIdOrSlug && isAdmin() ? tenantEndpoints.dataScopePolicy(tenantIdOrSlug) : null
  const { data, error, isLoading, mutate } = useSWR<DataScopePolicy>(key, fetcher, {
    revalidateOnFocus: false,
  })
  return {
    policy: data?.members_without_group_see,
    isLoading: key ? isLoading : false,
    isError: !!error,
    mutate,
  }
}

async function updatePolicy(url: string, { arg }: { arg: MembersWithoutGroupSee }) {
  return fetcherWithOptions<DataScopePolicy>(url, {
    method: 'PATCH',
    body: JSON.stringify({ members_without_group_see: arg }),
  })
}

export function useUpdateDataScopePolicy(tenantIdOrSlug: string | undefined) {
  const { trigger, isMutating } = useSWRMutation(
    tenantIdOrSlug ? tenantEndpoints.dataScopePolicy(tenantIdOrSlug) : null,
    updatePolicy
  )
  return { updatePolicy: trigger, isUpdating: isMutating }
}

/**
 * The members who would see nothing after switching off "everything"
 * (owner decision D2). Owners and admins only; fetched only while the
 * organization still shows everything.
 */
export function useDataScopeImpact(tenantIdOrSlug: string | undefined, enabled: boolean) {
  const { isAdmin } = usePermissions()
  const key = tenantIdOrSlug && enabled && isAdmin() ? tenantEndpoints.dataScopeImpact() : null
  const { data, error, isLoading, mutate } = useSWR<DataScopeImpact>(key, fetcher, {
    revalidateOnFocus: false,
  })
  return { impact: data, isLoading: key ? isLoading : false, isError: !!error, mutate }
}
