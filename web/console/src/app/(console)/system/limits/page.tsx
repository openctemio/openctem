'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useSelfServiceLimits } from '@console/features/admin-console/api/use-limits'
import { SelfServiceLimitsForm } from '@console/features/admin-console/components/self-service-limits-form'
import { StorageQuotaCard } from '@console/features/admin-console/components/storage-quota-card'
import { adminCan } from '@console/features/admin-console/types'

/**
 * System -> Limits: the limits self-service organizations start with. Any
 * administrator sees them; super admins change them. Limits of one
 * organization are set on that organization's Limits tab.
 */
export default function LimitsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useSelfServiceLimits()

  return (
    <Main>
      <PageHeader
        title={t('limits.console.page.title', 'Limits')}
        description={t(
          'limits.console.page.description',
          'Limits of organizations on this installation. None apply unless you set them.'
        )}
      />
      <div className="mt-5 space-y-5">
        {error ? (
          <ErrorState
            title={t('limits.console.defaults.loadError', 'the default limits')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <SelfServiceLimitsForm
            defaults={data}
            canEdit={adminCan(me.role, 'super_admin')}
            onSaved={() => void mutate()}
          />
        )}
        <StorageQuotaCard canEdit={adminCan(me.role, 'super_admin')} />
      </div>
    </Main>
  )
}
