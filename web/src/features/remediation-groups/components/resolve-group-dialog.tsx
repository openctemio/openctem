'use client'

import { useResolveRemediationGroup } from '../api/use-remediation-groups'
import type { RemediationGroup } from '../types'
import { useTranslation } from '@/context/i18n-provider'
import { MarkFixedDialog } from '@/features/remediation/components/mark-fixed-dialog'

interface ResolveGroupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  group: RemediationGroup | null
  onSuccess?: () => void
}

/** Marks a remediation group's open findings fixed (the shared "mark fixed" dialog). */
export function ResolveGroupDialog({
  open,
  onOpenChange,
  group,
  onSuccess,
}: ResolveGroupDialogProps) {
  const { t } = useTranslation()
  const { trigger, isMutating } = useResolveRemediationGroup(group?.key ?? '')
  return (
    <MarkFixedDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('remediation.markFixed.groupTitle', 'Mark the group fixed')}
      description={
        group
          ? t(
              'remediation.markFixed.groupDescription',
              '{count} open findings on {assets} assets: {title}',
              { count: group.finding_count, assets: group.asset_count, title: group.title }
            )
          : ''
      }
      openCount={group?.finding_count ?? 0}
      submitting={isMutating}
      onSubmit={(req) => trigger(req)}
      onSuccess={onSuccess}
    />
  )
}
