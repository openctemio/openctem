'use client'

import { Sparkles } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/**
 * The one label for anything an AI produced (API docs: architecture/ai-analysis.md,
 * "Labelling"). Every place that shows an AI actor, an AI-proposed request
 * or a value an AI set renders this badge; the gate test `ai-badge-gate.test.ts`
 * fails when a component that renders an AI actor does not.
 *
 * Sources:
 * - `ai_analyst`: an AI analyst, a service account that takes part in triage
 *   like a person (`name` names it). `accountable` lists the people and teams
 *   answerable for it; it shows as a muted second line;
 * - `ai_application`: an AI application a person connected over MCP (`client`
 *   names it; it is client-supplied text, shown as plain text);
 * - `ai_builtin`: the legacy in-process AI triage result.
 *
 * `verb` picks the wording on an approval request: "Proposed by" instead of the
 * plain label.
 */
export type AIBadgeSource = 'ai_builtin' | 'ai_analyst' | 'ai_application'
export type AIBadgeVerb = 'suggested' | 'proposed'

export interface AIBadgeProps {
  source: AIBadgeSource
  /** The AI application's name, for `ai_application`. */
  client?: string
  /** The AI analyst's name, for `ai_analyst`. */
  name?: string
  /** Names of the people and teams accountable for the AI analyst. */
  accountable?: string[]
  verb?: AIBadgeVerb
  /** A muted line under the badge telling the reader to check before acting. */
  withHint?: boolean
  className?: string
}

export function AIBadge({
  source,
  client,
  name,
  accountable,
  verb = 'suggested',
  withHint = false,
  className,
}: AIBadgeProps) {
  const { t } = useTranslation()
  const label = badgeLabel(t, source, verb, toDisplayText(client ?? '', 80), name)
  const owners = (accountable ?? [])
    .map((o) => toDisplayText(o, 80))
    .filter(Boolean)
    .join(', ')
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
      {source === 'ai_analyst' && owners && (
        <span className="text-xs text-muted-foreground" data-testid="ai-badge-accountable">
          {t('components.aiBadge.accountable', 'Accountable: {owners}', { owners })}
        </span>
      )}
      {withHint && (
        <span className="text-xs text-muted-foreground">
          {source === 'ai_application'
            ? t(
                'findings.aiProposal.appHint',
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

type T = ReturnType<typeof useTranslation>['t']

function badgeLabel(
  t: T,
  source: AIBadgeSource,
  verb: AIBadgeVerb,
  client: string,
  analyst?: string
): string {
  const who = toDisplayText(analyst ?? '', 80)
  switch (source) {
    case 'ai_application':
      return verb === 'proposed'
        ? t('findings.aiProposal.appBadge', 'Proposed by AI application: {client}', { client })
        : t('components.aiBadge.suggestedApplication', 'Suggested by AI application: {client}', {
            client,
          })
    case 'ai_analyst':
      if (verb === 'proposed') {
        return who
          ? t('components.aiBadge.proposedAnalystNamed', 'Proposed by AI analyst {name}', {
              name: who,
            })
          : t('components.aiBadge.proposedAnalyst', 'Proposed by AI analyst')
      }
      return who
        ? t('components.aiBadge.analystNamed', 'AI analyst {name}', { name: who })
        : t('components.aiBadge.analyst', 'AI analyst')
    default:
      return verb === 'proposed'
        ? t('findings.aiProposal.badge', 'Proposed by AI triage')
        : t('components.aiBadge.suggestedBuiltin', 'Suggested by AI triage')
  }
}
