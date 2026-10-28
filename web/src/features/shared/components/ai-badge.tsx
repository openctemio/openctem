'use client'

import { Sparkles } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/**
 * The one label for anything an AI produced (API docs: architecture/ai-analysis.md,
 * "Labelling"). Every place that shows an AI suggestion, an AI-proposed
 * request or a value an AI set renders this badge; the gate test
 * `ai-badge-gate.test.ts` fails when a component under the AI suggestion
 * folder does not.
 *
 * Sources:
 * - `ai_builtin`: the platform's built-in AI triage;
 * - `ai_analyst`: an AI analyst worker (platform-run or the organization's own);
 * - `ai_application`: an AI application a person connected over MCP (`client`
 *   names it; it is client-supplied text, shown as plain text).
 *
 * `verb` picks the wording: "Proposed by" on an approval request, "Suggested
 * by" on a suggestion.
 */
export type AIBadgeSource = 'ai_builtin' | 'ai_analyst' | 'ai_application'
export type AIBadgeVerb = 'suggested' | 'proposed'

/** The badge source for an AI run's executor. */
export function aiSourceOfExecutor(executor: string | undefined): AIBadgeSource {
  return executor === 'platform_worker' || executor === 'tenant_worker'
    ? 'ai_analyst'
    : 'ai_builtin'
}

export interface AIBadgeProps {
  source: AIBadgeSource
  /** The AI application's name, for `ai_application`. */
  client?: string
  verb?: AIBadgeVerb
  /** A muted line under the badge telling the reader to check before acting. */
  withHint?: boolean
  className?: string
}

export function AIBadge({
  source,
  client,
  verb = 'suggested',
  withHint = false,
  className,
}: AIBadgeProps) {
  const { t } = useTranslation()
  const name = toDisplayText(client ?? '', 80)
  const label = badgeLabel(t, source, verb, name)
  return (
    <span className={cn('inline-flex flex-col gap-1', className)}>
      <Badge
        variant="outline"
        className="w-fit gap-1 text-[11px]"
        data-testid="ai-badge"
        data-source={source}
      >
        <Sparkles className="h-3 w-3" aria-hidden />
        {label}
      </Badge>
      {withHint && (
        <span className="text-xs text-muted-foreground">
          {source === 'ai_application'
            ? t(
                'findings.aiProposal.appHint',
                'Written by an AI application for the requester, who cannot approve it. Check the finding before you approve it.'
              )
            : verb === 'proposed'
              ? t(
                  'findings.aiProposal.hint',
                  'An AI suggestion, not a decision. Check the finding before you approve it.'
                )
              : t(
                  'components.aiBadge.hint',
                  'An AI suggestion, not a decision. Check the finding before you apply it.'
                )}
        </span>
      )}
    </span>
  )
}

type T = ReturnType<typeof useTranslation>['t']

function badgeLabel(t: T, source: AIBadgeSource, verb: AIBadgeVerb, client: string): string {
  if (verb === 'proposed') {
    switch (source) {
      case 'ai_application':
        return t('findings.aiProposal.appBadge', 'Proposed by AI application: {client}', {
          client,
        })
      case 'ai_analyst':
        return t('components.aiBadge.proposedAnalyst', 'Proposed by AI analyst')
      default:
        return t('findings.aiProposal.badge', 'Proposed by AI triage')
    }
  }
  switch (source) {
    case 'ai_application':
      return t('components.aiBadge.suggestedApplication', 'Suggested by AI application: {client}', {
        client,
      })
    case 'ai_analyst':
      return t('components.aiBadge.suggestedAnalyst', 'Suggested by AI analyst')
    default:
      return t('components.aiBadge.suggestedBuiltin', 'Suggested by AI triage')
  }
}
