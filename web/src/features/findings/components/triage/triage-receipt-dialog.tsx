'use client'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { progress as progressOf, type TriageSession } from '../../lib/triage-session'
import { OUTCOME_LABELS } from './triage-queue-panel'

/**
 * The session's receipt, shown on Exit when something was decided: the
 * counts and what happened to each finding, so the person leaves knowing
 * what waits for a second approver.
 */
export function TriageReceiptDialog({
  open,
  onOpenChange,
  session,
  onLeave,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  session: TriageSession
  onLeave: () => void
}) {
  const { t } = useTranslation()
  const p = progressOf(session)
  const decided = session.items.filter((it) => {
    const o = session.outcomes[it.id]
    return o && o !== 'skipped' && o !== 'changed'
  })
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('findings.triageMode.receipt.title', 'Triage session')}</DialogTitle>
          <DialogDescription>
            {t(
              'findings.triageMode.doneBody',
              '{decided} decided, {sent} sent for approval, {skipped} skipped.',
              { decided: p.decided, sent: p.sentForApproval, skipped: p.skipped }
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <ul className="space-y-1.5 text-sm" data-testid="triage-receipt">
            {decided.map((it) => {
              const o = session.outcomes[it.id]!
              return (
                <li key={it.id} className="flex items-baseline justify-between gap-3">
                  <span dir="auto" className="min-w-0 truncate [unicode-bidi:isolate]">
                    {it.title}
                  </span>
                  <span className="shrink-0 font-mono text-xs text-muted-foreground uppercase">
                    {t(OUTCOME_LABELS[o].key, OUTCOME_LABELS[o].fallback)}
                  </span>
                </li>
              )
            })}
          </ul>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('findings.triageMode.receipt.keep', 'Keep triaging')}
          </Button>
          <Button onClick={onLeave}>
            {t('findings.triageMode.backToList', 'Back to the list')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
