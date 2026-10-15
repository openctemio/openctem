'use client'

import { useResolveRemediationCampaign } from '../api/use-remediation-campaigns'
import { useTranslation } from '@/context/i18n-provider'
import { MarkFixedDialog } from './mark-fixed-dialog'

interface ResolveCampaignDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  campaignId: string
  campaignName: string
  openCount: number
  onSuccess?: () => void
}

/** Marks the campaign's open findings fixed (the shared "mark fixed" dialog). */
export function ResolveCampaignDialog({
  open,
  onOpenChange,
  campaignId,
  campaignName,
  openCount,
  onSuccess,
}: ResolveCampaignDialogProps) {
  const { t } = useTranslation()
  const { trigger, isMutating } = useResolveRemediationCampaign(campaignId)
  return (
    <MarkFixedDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('remediation.markFixed.campaignTitle', 'Mark the campaign findings fixed')}
      description={t(
        'remediation.markFixed.campaignDescription',
        '{count} open findings in {name}.',
        { count: openCount, name: campaignName }
      )}
      openCount={openCount}
      submitting={isMutating}
      onSubmit={(req) => trigger(req)}
      onSuccess={onSuccess}
    />
  )
}
