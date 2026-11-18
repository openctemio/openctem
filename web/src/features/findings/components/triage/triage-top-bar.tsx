'use client'

import { Keyboard, Undo2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { TriageProgress } from '../../lib/triage-session'
import { Kbd } from './kbd'

/**
 * The actions of triage mode's page header: Undo last (with what is left to
 * undo), the keys, and Exit back to the list the person came from. All are
 * outline buttons: the page's one filled button is Confirm.
 *
 * Drawn from the first paint (Undo disabled until there is something to
 * undo), so the header never moves when the queue arrives.
 */
export function TriageHeaderActions({
  undoCount,
  busy,
  onUndo,
  onHelp,
  onExit,
}: {
  undoCount: number
  busy: boolean
  onUndo: () => void
  onHelp: () => void
  onExit: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="triage-header-actions">
      <Button
        variant="outline"
        onClick={onUndo}
        disabled={undoCount === 0 || busy}
        aria-keyshortcuts="u"
        data-triage-action="undo"
      >
        <Undo2 aria-hidden />
        {/* A phone has no keys: the short form keeps the three actions on one line. */}
        <span className="max-sm:hidden">{t('findings.triageMode.action.undo', 'Undo last')}</span>
        <Kbd className="max-sm:hidden">u</Kbd>
        <span className="font-normal text-muted-foreground tabular-nums max-sm:hidden">
          {t('findings.triageMode.action.undoHint', '{count} to undo', { count: undoCount })}
        </span>
        <span className="tabular-nums sm:hidden">
          {t('findings.triageMode.action.undoShort', 'Undo ({count})', { count: undoCount })}
        </span>
      </Button>
      <Button variant="outline" onClick={onHelp} aria-keyshortcuts="?" data-triage-action="help">
        <Keyboard aria-hidden />
        {t('findings.triageMode.action.help', 'All keys')}
        <Kbd className="max-sm:hidden">?</Kbd>
      </Button>
      <Button variant="outline" onClick={onExit} aria-keyshortcuts="Escape">
        <X aria-hidden />
        {t('findings.triageMode.exit', 'Exit')}
        {/* i18n-ok: the name printed on the key cap */}
        <Kbd className="max-sm:hidden">Esc</Kbd>
      </Button>
    </div>
  )
}

/**
 * Where the person is: the queue's name, the position in it, what this
 * session decided, and a progress bar. One line on a desktop; on a phone the
 * session's counts are in the bottom bar (`TriagePhoneBar`), hidden here by CSS
 * from the first paint, so nothing below moves.
 */
export function TriageStatusLine({
  queueLabel,
  progress,
}: {
  queueLabel: string
  progress: TriageProgress | null
}) {
  const { t } = useTranslation()
  const handled = progress
    ? progress.decided + progress.sentForApproval + progress.skipped + progress.changed
    : 0
  const pct =
    progress && progress.total > 0 ? Math.min(100, Math.round((handled / progress.total) * 100)) : 0
  const pending = '…'
  return (
    <div className="space-y-2" data-testid="triage-top-bar">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 text-sm">
        <p className="flex min-w-0 items-baseline gap-2">
          <span className="truncate font-medium">{queueLabel}</span>
          <span
            data-testid="triage-position"
            className="text-muted-foreground tabular-nums"
            aria-live="polite"
          >
            {!progress
              ? pending
              : progress.position > 0
                ? t('findings.triageMode.position', '{position} of {total}', {
                    position: progress.position,
                    total: progress.total,
                  })
                : t('findings.triageMode.positionDone', '{total} in the queue', {
                    total: progress.total,
                  })}
          </span>
        </p>
        {/* A phone shows the counts once, in the bar at the bottom of the screen. */}
        <p className="text-muted-foreground tabular-nums max-md:hidden" data-testid="triage-counts">
          {progress
            ? t(
                'findings.triageMode.counts',
                '{decided} decided, {sent} sent for approval, {skipped} skipped',
                {
                  decided: progress.decided,
                  sent: progress.sentForApproval,
                  skipped: progress.skipped,
                }
              )
            : pending}
        </p>
      </div>
      <div
        className="h-1 w-full overflow-hidden rounded bg-muted"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-label={t('findings.triageMode.progressLabel', 'Queue progress')}
      >
        <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
