'use client'

import { Sparkles } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { ApiApproval } from '../types'

/**
 * Marks an approval request an AI proposed: AI triage, or an AI application
 * the requester connected over MCP (`requested_via`), whose requester can
 * never approve it. A person still decides it; the justification is model
 * output (untrusted, rendered as text by the caller).
 */
export function AIProposalBadge({
  approval,
  withHint = false,
}: {
  approval: Pick<ApiApproval, 'requested_by_actor' | 'requested_via'>
  withHint?: boolean
}) {
  const { t } = useTranslation()
  const agent = approval.requested_via
  if (!agent && approval.requested_by_actor !== 'ai_triage') return null
  return (
    <span className="inline-flex flex-col gap-1">
      <Badge variant="outline" className="w-fit gap-1 text-[11px]">
        <Sparkles className="h-3 w-3" />
        {agent
          ? t('findings.aiProposal.agentBadge', 'Proposed by AI agent: {client}', { client: agent })
          : t('findings.aiProposal.badge', 'Proposed by AI triage')}
      </Badge>
      {withHint && (
        <span className="text-xs text-muted-foreground">
          {agent
            ? t(
                'findings.aiProposal.agentHint',
                'Written by an AI application for the requester, who cannot approve it. Check the finding before you approve it.'
              )
            : t(
                'findings.aiProposal.hint',
                'An AI suggestion, not a decision. Check the finding before you approve it.'
              )}
        </span>
      )}
    </span>
  )
}
