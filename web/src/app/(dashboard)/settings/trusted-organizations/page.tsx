'use client'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { TrustedOrganizations } from '@/features/organization/components/trusted-organizations'
import { usePermissions } from '@/lib/permissions'

/**
 * Settings › Trusted organizations (api RFC-058): partner organizations whose
 * people sign in here with their own company's SSO, and organizations that
 * trust this one. Owners change trusts; admins read them.
 */
export default function TrustedOrganizationsPage() {
  const { isOwner, isAtLeast, isLoading } = usePermissions()
  return (
    <Main>
      <PageHeader
        title="Trusted organizations"
        description="Partner organizations whose people sign in here with their own company's SSO. A trust applies once both owners agree."
      />
      <div className="mt-5">
        {!isLoading && <TrustedOrganizations canRead={isAtLeast('admin')} isOwner={isOwner()} />}
      </div>
    </Main>
  )
}
