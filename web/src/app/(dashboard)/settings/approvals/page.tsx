'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { useFindingApprovalSettings } from '@/features/findings/api/use-findings-api'
import { FindingApprovalsForm } from '@/features/findings/components/finding-approvals-form'
import { Button } from '@/components/ui/button'
import { SettingsPage, SettingsRow } from '@/features/shared'
import { useScanGovernance } from '@/lib/api/scan-approval-hooks'
import { usePermissions, Permission } from '@/lib/permissions'
import { useNavItemAccess } from '@/lib/permissions/use-filtered-sidebar'

/** Who may open the scan approval page (its route's gate). */
const SCAN_APPROVAL = {
  permission: Permission.ScansRead,
  module: 'scans',
}

/**
 * Settings > Approvals: who decides false positives and accepted risks, and
 * who is told. Reading needs settings:read (the route) and findings:read (the
 * API); saving needs an owner or administrator with settings:write and a
 * recent sign-in. Each approval type is one row with what is set, opening
 * its editor on demand. Scan approval keeps its own page and gate: its row,
 * with the mode in force, is shown to whoever may open that page.
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
        after={canSee(SCAN_APPROVAL) && <ScanApprovalRow />}
      />
    </SettingsPage>
  )
}

/** Scan approval: the mode in force, and the way to its own page. */
function ScanApprovalRow() {
  const { t } = useTranslation()
  const { data } = useScanGovernance()
  const summary = !data
    ? t(
        'settings.desc.scan-approval',
        'Which scans need a person’s approval before they run: off by default.'
      )
    : data.mode === 'strict'
      ? t(
          'settings.approvals.scansStrict',
          'Scans your rules catch need two approvers, and scope entries need approval too.'
        )
      : data.mode === 'on'
        ? t('settings.approvals.scansOn', 'Scans your rules catch need approval before they run.')
        : t('settings.approvals.scansOff', 'No scan needs approval.')
  return (
    <SettingsRow id="scans" label={t('settings.approvals.scansTitle', 'Scans')} hint={summary}>
      <Button asChild variant="outline" size="sm">
        <Link
          href="/settings/scanning/scan-approval"
          aria-label={t('settings.approvals.scansOpen', 'Open scan approval')}
        >
          {t('settings.approvals.scansOpenShort', 'Open')}
        </Link>
      </Button>
    </SettingsRow>
  )
}
