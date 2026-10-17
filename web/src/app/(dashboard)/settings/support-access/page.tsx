'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader } from '@/features/shared'
import { SupportAccessSettings } from '@/features/support-access/components/support-access-settings'
import { usePermissions } from '@/lib/permissions'

/**
 * Settings › Support access (api RFC-063): read-only, time-boxed, audited
 * access for platform support. Owners grant; owners and admins revoke and see
 * the history. The API enforces every rule; the page only hides actions.
 */
export default function SupportAccessPage() {
  const { t } = useTranslation()
  const { isOwner, isAtLeast, isLoading } = usePermissions()
  return (
    <Main>
      <PageHeader
        title={t('supportAccess.title', 'Support access')}
        description={t(
          'supportAccess.description',
          'Let platform support read your data, read-only and for a limited time, while they help you.'
        )}
      />
      <div className="mt-5">
        {!isLoading && <SupportAccessSettings canRead={isAtLeast('admin')} isOwner={isOwner()} />}
      </div>
    </Main>
  )
}
