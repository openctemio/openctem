'use client'

import { AIBadge } from '@/features/shared/components/ai-badge'
import type { ApiApproval } from '../types'

/**
 * Marks an approval request an AI proposed: AI triage or an AI agent
 * (`requested_by_actor`), or an AI application the requester connected over
 * MCP (`requested_via`), whose requester can never approve it. A person still
 * decides it; the justification is model output (untrusted, rendered as text
 * by the caller). The label itself is the shared `AIBadge`.
 */
export function AIProposalBadge({
  approval,
  withHint = false,
}: {
  approval: Pick<ApiApproval, 'requested_by_actor' | 'requested_via'>
  withHint?: boolean
}) {
  const via = approval.requested_via
  if (via) {
    return <AIBadge source="ai_application" client={via} verb="proposed" withHint={withHint} />
  }
  const actor = approval.requested_by_actor
  if (actor !== 'ai_triage' && actor !== 'ai_agent') return null
  return (
    <AIBadge
      source={actor === 'ai_agent' ? 'ai_agent' : 'ai_builtin'}
      verb="proposed"
      withHint={withHint}
    />
  )
}
