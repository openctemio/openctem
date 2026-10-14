'use client'

import { Sparkles } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { ApiApproval } from '../types'

/**
 * Marks an approval request that AI triage proposed. A person still decides
 * it; the justification is the model's rationale (untrusted, rendered as text
 * by the caller).
 */
export function AIProposalBadge({
  approval,
  withHint = false,
}: {
  approval: Pick<ApiApproval, 'requested_by_actor'>
  withHint?: boolean
}) {
  const { t } = useTranslation()
  if (approval.requested_by_actor !== 'ai_triage') return null
  return (
    <span className="inline-flex flex-col gap-1">
      <Badge variant="outline" className="w-fit gap-1 text-[11px]">
        <Sparkles className="h-3 w-3" />
        {t('findings.aiProposal.badge', 'Proposed by AI triage')}
      </Badge>
      {withHint && (
        <span className="text-xs text-muted-foreground">
          {t(
            'findings.aiProposal.hint',
            'An AI suggestion, not a decision. Check the finding before you approve it.'
          )}
        </span>
      )}
    </span>
  )
}
