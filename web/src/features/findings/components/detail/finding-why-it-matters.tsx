'use client'

/**
 * "Why it matters" — how urgent the finding is for this organisation and why:
 * the P-class with the classifier's reason, then the signals behind it
 * grouped as exploitation / exposure / business impact. Answers "how bad is
 * this for us?" in the first screen, where severity alone cannot.
 *
 * Everything shown comes from the finding response. The score breakdown
 * (GET …/priority-explanation) is fetched only when the reader opens "How
 * this was scored".
 */

import { useState } from 'react'
import Link from 'next/link'
import { Activity, Building2, ChevronRight, Gavel, Globe, ShieldQuestion } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { PriorityClassBadge } from '../priority-class-badge'
import { ScoreBreakdown } from './priority-explanation-card'
import { useFindingPriorityExplanation } from '../../api/use-finding-priority-explanation'
import { PRIORITY_CLASS_CONFIG, type FindingDetail } from '../../types'
import { PriorityClassSla } from '@/features/sla/components/priority-class-sla'
import { riskSignals, type RiskSignal, type SignalGroup } from '../../lib/finding-signals'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'

/**
 * The API caps a finding at P2 while its asset's attribution is not
 * confirmed (RFC-036 §6.8) and says so in the reason with this phrase
 * (vulnerability.AttributionCapReason).
 */
export const ATTRIBUTION_CAP_PHRASE = 'capped at P2 until ownership is confirmed'

export function isAttributionCapped(reason: string | null | undefined): boolean {
  return !!reason && reason.includes(ATTRIBUTION_CAP_PHRASE)
}

const GROUPS: { key: SignalGroup; label: string; icon: React.ElementType }[] = [
  { key: 'exploitation', label: 'Exploitation', icon: Activity },
  { key: 'exposure', label: 'Exposure', icon: Globe },
  { key: 'impact', label: 'Business impact', icon: Building2 },
]

const EFFECT_DOT: Record<RiskSignal['effect'], string> = {
  raises: 'bg-destructive',
  lowers: 'bg-success',
  neutral: 'bg-muted-foreground/50',
}

const EFFECT_WORD: Record<RiskSignal['effect'], string> = {
  raises: 'raises priority',
  lowers: 'lowers priority',
  neutral: 'context',
}

function sentence(s: string): string {
  const t = s.trim()
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : t
}

export function SignalChip({ signal }: { signal: RiskSignal }) {
  return (
    <li
      className="inline-flex min-h-7 items-center gap-1.5 rounded-md border bg-card px-2 py-0.5 text-sm"
      title={signal.detail}
      data-effect={signal.effect}
    >
      <span
        aria-hidden
        className={cn('size-1.5 shrink-0 rounded-full', EFFECT_DOT[signal.effect])}
      />
      <span>{signal.label}</span>
      <span className="sr-only">({EFFECT_WORD[signal.effect]})</span>
    </li>
  )
}

function ScoreDetails({ findingId }: { findingId: string }) {
  const { explanation, isLoading } = useFindingPriorityExplanation(findingId)
  if (isLoading) return <Skeleton className="mt-2 h-28 w-full max-w-md" />
  if (!explanation) {
    return (
      <p className="mt-2 text-sm text-muted-foreground">No score breakdown for this finding.</p>
    )
  }
  return (
    <div className="mt-2 max-w-md space-y-2">
      {explanation.source === 'rule' && explanation.rule_name && (
        <Badge variant="secondary" className="gap-1">
          <Gavel className="h-3 w-3" aria-hidden />
          Set by rule: {explanation.rule_name}
        </Badge>
      )}
      {explanation.score_breakdown && <ScoreBreakdown breakdown={explanation.score_breakdown} />}
    </div>
  )
}

export interface FindingWhyItMattersProps {
  finding: FindingDetail
  /** `compact` for the drawer: one flat list of chips, no group labels. */
  compact?: boolean
  className?: string
}

export function FindingWhyItMatters({ finding, compact, className }: FindingWhyItMattersProps) {
  const [scoreOpen, setScoreOpen] = useState(false)
  const signals = riskSignals(finding)
  const pc = finding.priorityClass
  if (!pc && signals.length === 0) return null

  const cfg = pc ? PRIORITY_CLASS_CONFIG[pc] : undefined
  const reason = finding.priorityClassReason

  return (
    <section
      aria-labelledby={`why-${finding.id}`}
      data-slot="finding-why"
      className={cn('rounded-lg border bg-card p-4', className)}
    >
      <h2 id={`why-${finding.id}`} className="text-sm font-semibold">
        Why it matters
      </h2>

      {pc && cfg && (
        <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1">
          <PriorityClassBadge priorityClass={pc} showTooltip={false} />
          <span className="text-sm font-medium">{cfg.description.split(' — ')[0]}</span>
          <PriorityClassSla
            priorityClass={pc}
            assetId={finding.assets[0]?.id}
            variant="sentence"
            className="text-sm text-muted-foreground before:content-['·_']"
          />
          {finding.priorityClassOverride && (
            <Badge variant="outline" className="text-xs">
              Set manually
            </Badge>
          )}
        </div>
      )}
      {reason && <p className="mt-1.5 text-sm text-muted-foreground">{sentence(reason)}.</p>}
      {isAttributionCapped(reason) && (
        <div
          role="note"
          aria-label="Ownership not confirmed"
          className="mt-2 flex flex-wrap items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-2 text-sm"
        >
          <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
          <span className="min-w-0 flex-1">
            This asset has not been confirmed as your organisation&apos;s, so the finding is held at
            P2.
          </span>
          {isLinkableAssetId(finding.assets[0]?.id) && (
            <Link
              href={assetDetailHref(finding.assets[0].id)}
              className="font-medium underline underline-offset-2"
            >
              Verify ownership
            </Link>
          )}
        </div>
      )}

      {signals.length > 0 &&
        (compact ? (
          <ul className="mt-3 flex flex-wrap gap-1.5" aria-label="Risk signals">
            {signals.map((s) => (
              <SignalChip key={s.key} signal={s} />
            ))}
          </ul>
        ) : (
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            {GROUPS.map((g) => {
              const items = signals.filter((s) => s.group === g.key)
              if (items.length === 0) return null
              const Icon = g.icon
              return (
                <div key={g.key} className="min-w-0">
                  <h3 className="mb-1.5 flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Icon className="h-3.5 w-3.5" aria-hidden />
                    {g.label}
                  </h3>
                  <ul className="flex flex-wrap gap-1.5" aria-label={g.label}>
                    {items.map((s) => (
                      <SignalChip key={s.key} signal={s} />
                    ))}
                  </ul>
                </div>
              )
            })}
          </div>
        ))}

      {pc && !compact && (
        <details
          className="group mt-3 text-sm"
          onToggle={(e) => setScoreOpen((e.target as HTMLDetailsElement).open)}
        >
          <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm text-xs text-muted-foreground select-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [&::-webkit-details-marker]:hidden">
            <ChevronRight
              className="h-3 w-3 transition-transform group-open:rotate-90"
              aria-hidden
            />
            How this was scored
          </summary>
          {scoreOpen && <ScoreDetails findingId={finding.id} />}
        </details>
      )}
    </section>
  )
}
