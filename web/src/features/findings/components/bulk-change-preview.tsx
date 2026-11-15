'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import {
  evaluateFindingTransitions,
  type EvaluatedTransition,
} from '@/features/findings/api/use-finding-transitions'
import { summarizeDryRun } from '@/features/findings/lib/transition-reasons'

/**
 * What a bulk change will do, shown in its confirm dialog before anything is
 * written. Checked rows and a status: the server's dry run (the transition
 * engine) says how many will change and why the others will not. A filter
 * selection: the server applies the change in the caller's data scope and
 * checks every finding again as it goes, so the dialog says that and the
 * result lists what it skipped.
 */
export function BulkChangePreview({
  selection,
  status,
  note,
  onResults,
}: {
  selection: { kind: 'ids'; ids: string[] } | { kind: 'filter'; total: number }
  /** The target status; omitted for an assignment (no dry run). */
  status?: string
  /** The note typed so far (a move may need a minimum length). */
  note?: string
  /** The dry run's raw results, so applying does not ask again. */
  onResults?: (status: string, results: EvaluatedTransition[]) => void
}) {
  const { t } = useTranslation()
  const ids = selection.kind === 'ids' ? selection.ids : null
  const idsKey = ids ? ids.join(',') : ''
  const [results, setResults] = useState<{ key: string; list: EvaluatedTransition[] } | null>(null)
  const [failed, setFailed] = useState(false)
  const key = `${status ?? ''}|${idsKey}`

  useEffect(() => {
    if (!status || !ids || ids.length === 0) return
    let live = true
    setFailed(false)
    evaluateFindingTransitions(ids, status)
      .then((list) => {
        if (!live) return
        setResults({ key, list })
        onResults?.(status, list)
      })
      .catch(() => live && setFailed(true))
    return () => {
      live = false
    }
    // ids are compared by value (idsKey); onResults is a setter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  if (selection.kind === 'filter') {
    return (
      <p className="text-sm text-muted-foreground" data-testid="bulk-preview">
        {t(
          'findings.bulk.previewFilter',
          'This changes up to {count} findings that match, in your data scope. The server checks each one again as it applies the change; any it skips are listed when it ends.',
          { count: selection.total.toLocaleString() }
        )}
      </p>
    )
  }
  if (!status) return null
  if (failed) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="bulk-preview">
        {t(
          'findings.bulk.previewUnavailable',
          'Could not check the findings first; any that cannot move are skipped and listed afterwards.'
        )}
      </p>
    )
  }
  if (!results || results.key !== key) {
    return (
      <p
        className="flex items-center gap-2 text-sm text-muted-foreground"
        data-testid="bulk-preview"
      >
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
        {t('findings.bulk.previewChecking', 'Checking which findings can move…')}
      </p>
    )
  }
  const summary = summarizeDryRun(t, results.list, { note })
  const refusedCount = summary.refused.reduce((n, r) => n + r.count, 0)
  return (
    <div className="space-y-1 text-sm" data-testid="bulk-preview" aria-live="polite">
      <p>
        {t('findings.bulk.previewWillChange', '{count} will change', {
          count: summary.allowed.length.toLocaleString(),
        })}
      </p>
      {refusedCount > 0 && (
        <>
          <p className="text-muted-foreground">
            {t('findings.bulk.previewWillNotChange', '{count} will not change:', {
              count: refusedCount.toLocaleString(),
            })}
          </p>
          <ul className="list-disc ps-5 text-muted-foreground">
            {summary.refused.map((r) => (
              <li key={r.reason}>
                {r.reason} ({r.count.toLocaleString()})
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
