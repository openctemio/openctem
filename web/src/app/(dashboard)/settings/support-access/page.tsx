'use client'

import { Main } from '@/components/layout'
import { SupportAccessSettings } from '@/features/support-access/components/support-access-settings'
import { usePermissions } from '@/lib/permissions'

/**
 * Settings › Support access (api RFC-063): read-only, time-boxed, audited
 * access for platform support. Owners grant; owners and admins revoke and see
 * the history. The API enforces every rule; the page only hides actions.
 */
export default function SupportAccessPage() {
  const { isOwner, isAtLeast, isLoading } = usePermissions()
  return (
    <Main>
      {/* The settings render the page header (with Grant access) themselves. */}
      {!isLoading && <SupportAccessSettings canRead={isAtLeast('admin')} isOwner={isOwner()} />}
    </Main>
  )
}
