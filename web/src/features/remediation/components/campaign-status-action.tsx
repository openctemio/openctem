'use client'

/**
 * A campaign's one main action, by status: Start (draft), Complete (active;
 * disabled with the reason while tasks are still open) or Reopen (completed).
 * Shared by the campaign page and the campaign's quick-view sheet. The caller
 * renders it only for a person who may change the campaign
 * (findings remediation write and the campaign's can_edit); the API decides.
 */

import { CheckCheck, Play, RotateCcw } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { RemediationCampaign } from '../api/use-remediation-campaigns'

export type CampaignStatusChange = 'active' | 'completed' | 'canceled'

export function CampaignStatusAction({
  campaign: c,
  busy,
  onSetStatus,
}: {
  campaign: RemediationCampaign
  busy: boolean
  onSetStatus: (status: CampaignStatusChange, success: string) => void
}) {
  const { t } = useTranslation()
  const live = c.summary.live_tasks
  if (c.status === 'draft') {
    return (
      <Button
        disabled={busy}
        onClick={() => onSetStatus('active', t('remediationCampaigns.toast.started'))}
      >
        <Play className="size-4" aria-hidden />
        {t('remediationCampaigns.actions.start')}
      </Button>
    )
  }
  if (c.status === 'active') {
    if (live > 0) {
      const reason = t(
        `remediationCampaigns.detail.completeBlocked.${live === 1 ? 'one' : 'other'}`,
        undefined,
        { count: live }
      )
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} aria-describedby={`complete-blocked-${c.id}`}>
              <Button disabled aria-disabled>
                <CheckCheck className="size-4" aria-hidden />
                {t('remediationCampaigns.actions.complete')}
              </Button>
            </span>
          </TooltipTrigger>
          <TooltipContent id={`complete-blocked-${c.id}`}>{reason}</TooltipContent>
        </Tooltip>
      )
    }
    return (
      <Button
        disabled={busy}
        onClick={() => onSetStatus('completed', t('remediationCampaigns.toast.completed'))}
      >
        <CheckCheck className="size-4" aria-hidden />
        {t('remediationCampaigns.actions.complete')}
      </Button>
    )
  }
  if (c.status === 'completed') {
    return (
      <Button
        variant="outline"
        disabled={busy}
        onClick={() => onSetStatus('active', t('remediationCampaigns.toast.reopened'))}
      >
        <RotateCcw className="size-4" aria-hidden />
        {t('remediationCampaigns.actions.reopen')}
      </Button>
    )
  }
  return null
}
