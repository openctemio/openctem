'use client'

import { OrganizationSettings } from '@/features/organization/components/organization-settings'

/** Settings › Security › Authentication: how people sign in and who may join. */
export default function OrganizationAuthenticationPage() {
  return <OrganizationSettings view="authentication" />
}
