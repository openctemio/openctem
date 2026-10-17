'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useFindingApprovalSettings } from '@/features/findings/api/use-findings-api'
import { FindingApprovalSettingsForm } from '@/features/findings/components/finding-approval-settings-form'
import { ApprovalPolicyForm } from '@/features/findings/components/approval-policy-form'
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
          <div className="space-y-8">
            <FindingApprovalSettingsForm
              settings={data}
              canEdit={can(Permission.SettingsWrite)}
              onSaved={(next) => void mutate(next, { revalidate: false })}
            />
            <section className="space-y-3">
              <div>
                <h2 className="text-lg font-semibold">
                  {t('findingApprovals.policy.title', 'Approval policy')}
                </h2>
                <p className="text-sm text-muted-foreground">
                  {t(
                    'findingApprovals.policy.description',
                    'How many people approve each request, who they are, and how long a decision lasts. Changes are audited and every approver is told.'
                  )}
                </p>
              </div>
              <ApprovalPolicyForm
                settings={data}
                canEdit={can(Permission.SettingsWrite)}
                onSaved={(next) => void mutate(next, { revalidate: false })}
              />
            </section>
          </div>
        )}
      </div>
    </Main>
  )
}
