'use client'

import useSWR from 'swr'
import { del, get, post } from '@/lib/api/client'
import type { EASMVerifiedDomain, EASMVerifiedDomainList } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

export const EASM_VERIFIED_DOMAINS_KEY = '/api/v1/easm/verified-domains'

/**
 * GET /api/v1/easm/verified-domains (research/22 P0-10): the organization's
 * DNS-TXT verified domains. Rows it added are EASM-only (they never admit SSO
 * users); rows a platform administrator set up for SSO come back read-only
 * (`managed`). Fetched only with scope:read and the attack_surface module.
 */
export function useEASMVerifiedDomains() {
  const { can } = usePermissions()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()
  const enabled =
    can(Permission.ScopeRead) && !modulesLoading && moduleIds.includes('attack_surface')
  const { data, error, isLoading, mutate } = useSWR<EASMVerifiedDomainList>(
    enabled ? EASM_VERIFIED_DOMAINS_KEY : null,
    get,
    { revalidateOnFocus: false }
  )
  return { domains: data?.data ?? [], error, isLoading: isLoading || modulesLoading, mutate }
}

/** POST /api/v1/easm/verified-domains: returns the TXT record to publish. */
export function addVerifiedDomain(domain: string) {
  return post<EASMVerifiedDomain>(EASM_VERIFIED_DOMAINS_KEY, { domain })
}

/** POST /api/v1/easm/verified-domains/{id}/verify: at most 10 per hour. */
export function checkVerifiedDomain(id: string) {
  return post<EASMVerifiedDomain>(
    `${EASM_VERIFIED_DOMAINS_KEY}/${encodeURIComponent(id)}/verify`,
    {}
  )
}

/** DELETE /api/v1/easm/verified-domains/{id} */
export function removeVerifiedDomain(id: string) {
  return del(`${EASM_VERIFIED_DOMAINS_KEY}/${encodeURIComponent(id)}`)
}

/** The row that proves a seed: the same name, or a parent of it. */
export function domainFor(
  seed: string | undefined,
  domains: EASMVerifiedDomain[]
): EASMVerifiedDomain | undefined {
  if (!seed) return undefined
  const name = seed.toLowerCase()
  return (
    domains.find((d) => d.domain === name) ??
    domains.find((d) => !!d.domain && d.status === 'verified' && name.endsWith(`.${d.domain}`))
  )
}
