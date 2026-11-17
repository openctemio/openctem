'use client'

import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useFindingApprovalSettings } from '@/features/findings/api/use-findings-api'
import { FindingApprovalsForm } from '@/features/findings/components/finding-approvals-form'
import { SettingsPage, SettingsRow, SettingsSection } from '@/features/shared'
import { usePermissions, Permission } from '@/lib/permissions'
import { useNavItemAccess } from '@/lib/permissions/use-filtered-sidebar'

/** Where scan approval is set, and who may open it (its route's gate). */
const SCAN_APPROVAL = {
  url: '/settings/scanning/scan-approval',
  permission: Permission.ScansRead,
  module: 'scans',
}

/**
 * Settings > Approvals: who decides false positives and accepted risks, and
 * who is told. Reading needs settings:read (the route) and findings:read (the
 * API); saving needs an owner or administrator with settings:write and a
 * recent sign-in. Scan approval keeps its own page and gate: a link to it is
 * shown to whoever may open it.
 */
export default function ApprovalsSettingsPage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canSee = useNavItemAccess()
  const { data, error, isLoading, mutate } = useFindingApprovalSettings()
  const canEdit = can(Permission.SettingsWrite)

  const title = t('settings.item.approvals', 'Approvals')
  const description = t(
    'settings.desc.approvals',
    'Who decides false positives and accepted risks, and who is told.'
  )

  if (error || isLoading || !data) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={error ? 'error' : 'loading'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  return (
    <SettingsPage title={title} description={description} readOnly={!canEdit}>
      <FindingApprovalsForm
        settings={data}
        canEdit={canEdit}
        onSaved={(next) => void mutate(next, { revalidate: false })}
        after={
          canSee(SCAN_APPROVAL) && (
            <SettingsSection
              framed
              id="scans"
              title={t('settings.approvals.scansTitle', 'Scans')}
              description={t(
                'settings.approvals.scansDesc',
                'Which scans wait for a person’s approval before they run is set on its own page, with its own permission.'
              )}
            >
              <SettingsRow
                label={t('settings.item.scan-approval', 'Scan approval')}
                hint={t(
                  'settings.desc.scan-approval',
                  'Which scans need a person’s approval before they run: off by default.'
                )}
              >
                <Button variant="outline" asChild>
                  <Link href={SCAN_APPROVAL.url}>
                    {t('settings.approvals.scansOpen', 'Open scan approval')}
                  </Link>
                </Button>
              </SettingsRow>
            </SettingsSection>
          )
        }
      />
    </SettingsPage>
  )
}
