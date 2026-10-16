'use client'

import useSWR from 'swr'
import { Globe } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { useAuthProviders } from '@/features/auth/api/use-auth-providers'
import { fetcher } from '@/lib/api/client'

/**
 * The data region of a new organization (api RFC-104): the deployment's,
 * shown as fixed text on the create form. Nothing when the deployment names
 * no region.
 */
export function NewOrganizationRegion() {
  const { t } = useTranslation()
  const { data } = useAuthProviders()
  const region = data?.deployment_region
  if (!region) return null
  return (
    <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
      <Globe className="h-4 w-4" />
      {t('org.region.new', undefined, { region })}
    </p>
  )
}

/**
 * The data region of the current organization, fixed since it was created.
 * Nothing for an organization from before regions were named.
 */
export function OrganizationRegion({ slug }: { slug?: string }) {
  const { t } = useTranslation()
  const { data } = useSWR<{ region?: string }>(slug ? `/api/v1/tenants/${slug}` : null, fetcher, {
    revalidateOnFocus: false,
  })
  if (!data?.region) return null
  return (
    <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <Globe className="h-3.5 w-3.5" />
      {t('org.region.current', undefined, { region: data.region })}
    </p>
  )
}
