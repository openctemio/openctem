'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useFindingApprovalSettings } from '@/features/findings/api/use-findings-api'
import { FindingApprovalSettingsForm } from '@/features/findings/components/finding-approval-settings-form'
import { ErrorState, PageHeader } from '@/features/shared'
import { usePermissions, Permission } from '@/lib/permissions'

/** Settings > Finding approvals. */
export default function FindingApprovalSettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { data, error, isLoading, mutate } = useFindingApprovalSettings()

  return (
    <Main>
      <PageHeader
        title={t('settings.item.finding-approvals', 'Finding approvals')}
        description={t(
          'settings.desc.finding-approvals',
          'Who decides false positives and accepted risks, and who is told.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('findingApprovals.settings.loadTitle', 'finding approval settings')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-64 w-full rounded-xl" />
        ) : (
          <FindingApprovalSettingsForm
            settings={data}
            canEdit={can(Permission.SettingsWrite)}
            onSaved={(next) => void mutate(next, { revalidate: false })}
          />
        )}
      </div>
    </Main>
  )
}
