'use client'

/**
 * Explains the dashed lines on a trend chart: the dates a scoring model or
 * the organization's scoring settings changed (API docs:
 * architecture/scoring-versions.md). Snapshots are never recomputed, so the
 * values before and after such a date come from different scoring and a step
 * there may not be a change in risk.
 */

import { useTranslation } from '@/context/i18n-provider'
import type { RiskTrendPoint, ScoringChangeMarker } from '../../hooks/use-ctem-dashboard'

interface ScoringChangeNoteProps {
  points: RiskTrendPoint[]
  kind: ScoringChangeMarker['kind']
}

export function ScoringChangeNote({ points, kind }: ScoringChangeNoteProps) {
  const { t } = useTranslation()
  const changes = points.flatMap((p) =>
    (p.scoring_changes ?? []).filter((c) => c.kind === kind).map((c) => ({ ...c, at: p.date }))
  )
  if (changes.length === 0) return null
  const seen = new Set<string>()
  const unique = changes.filter((c) => {
    const k = `${c.at}|${c.source}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return (
    <ul className="mt-2 space-y-0.5 text-[11px] text-muted-foreground">
      {unique.map((c) => (
        <li key={`${c.at}-${c.source}`}>
          {t(
            'insights.scoringChange.note',
            'Scoring changed on {date} ({what}): values before and after are not directly comparable.',
            {
              date: new Date(c.at).toLocaleDateString(),
              what: t(`insights.scoringChange.source.${c.source}`, c.source.replace(/_/g, ' ')),
            }
          )}
        </li>
      ))}
    </ul>
  )
}
