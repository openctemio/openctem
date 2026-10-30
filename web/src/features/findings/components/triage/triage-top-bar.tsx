'use client'

import { ChevronLeft, ChevronRight, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { TriageProgress } from '../../lib/triage-session'
import { Kbd } from './kbd'

/**
 * Triage mode's top bar: which queue, how far along, previous / next, and
 * Exit back to the list the person came from.
 */
export function TriageTopBar({
  queueLabel,
  progress,
  canPrev,
  canNext,
  onPrev,
  onNext,
  onExit,
}: {
  queueLabel: string
  progress: TriageProgress
  canPrev: boolean
  canNext: boolean
  onPrev: () => void
  onNext: () => void
  onExit: () => void
}) {
  const { t } = useTranslation()
  const pct =
    progress.total > 0
      ? Math.min(
          100,
          Math.round(
            ((progress.decided + progress.sentForApproval + progress.skipped + progress.changed) /
              progress.total) *
              100
          )
        )
      : 0
  return (
    <div
      className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b bg-card px-4 py-2.5"
      data-testid="triage-top-bar"
    >
      <div className="flex min-w-0 items-baseline gap-2">
        <span className="text-xs font-semibold tracking-wide text-primary uppercase">
          {t('findings.triageMode.title', 'Triage')}
        </span>
        <span className="truncate text-sm font-semibold">{queueLabel}</span>
      </div>
      <div className="flex min-w-0 flex-1 items-center gap-3 font-mono text-xs text-muted-foreground">
        <div
          className="hidden h-1 w-40 shrink-0 overflow-hidden rounded bg-muted sm:block"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
          aria-label={t('findings.triageMode.progressLabel', 'Queue progress')}
        >
          <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
        </div>
        <span data-testid="triage-position" aria-live="polite">
          {progress.position > 0
            ? t('findings.triageMode.position', '{position} of {total}', {
                position: progress.position,
                total: progress.total,
              })
            : t('findings.triageMode.positionDone', '{total} in the queue', {
                total: progress.total,
              })}
        </span>
        <span className="hidden md:inline" data-testid="triage-counts">
          {t(
            'findings.triageMode.counts',
            '{decided} decided, {sent} sent for approval, {skipped} skipped',
            {
              decided: progress.decided,
              sent: progress.sentForApproval,
              skipped: progress.skipped,
            }
          )}
        </span>
      </div>
      <div className="flex items-center gap-1.5">
        <Button
          variant="outline"
          size="sm"
          onClick={onPrev}
          disabled={!canPrev}
          aria-keyshortcuts="k"
          aria-label={t('findings.triageMode.prev', 'Previous finding')}
        >
          <ChevronLeft className="h-4 w-4 rtl:rotate-180" aria-hidden />
          <Kbd>k</Kbd>
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onNext}
          disabled={!canNext}
          aria-keyshortcuts="j"
          aria-label={t('findings.triageMode.next', 'Next finding')}
        >
          <Kbd>j</Kbd>
          <ChevronRight className="h-4 w-4 rtl:rotate-180" aria-hidden />
        </Button>
        <Button variant="ghost" size="sm" onClick={onExit} aria-keyshortcuts="Escape">
          <X className="h-4 w-4 sm:me-1" aria-hidden />
          {t('findings.triageMode.exit', 'Exit')}
          <Kbd className="ms-1.5">Esc</Kbd>
        </Button>
      </div>
    </div>
  )
}
