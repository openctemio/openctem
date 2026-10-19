'use client'

/**
 * Asks why a finding's severity changes. The API requires a reason for every
 * change (an analyst override or a restore of the reported severity); a
 * downgrade may wait for approval under the organization's policy, which the
 * dialog says up front.
 */

import { useState } from 'react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'

const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
}

/** Whether moving from one severity to another lowers it. */
export function isSeverityDowngrade(from: string, to: string): boolean {
  return (SEVERITY_RANK[to] ?? 0) < (SEVERITY_RANK[from] ?? 0)
}

export const SEVERITY_REASON_MAX = 1000

interface SeverityChangeDialogProps {
  open: boolean
  /** Current effective severity. */
  from: string
  /** Target severity (the reported one for a restore). */
  to: string
  restore?: boolean
  busy?: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (reason: string) => void
}

export function SeverityChangeDialog({
  open,
  from,
  to,
  restore,
  busy,
  onOpenChange,
  onConfirm,
}: SeverityChangeDialogProps) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const trimmed = reason.trim()
  const fromLabel = t(`severity.${from}`, from)
  const toLabel = t(`severity.${to}`, to)
  const downgrade = isSeverityDowngrade(from, to)
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {restore
              ? t('findings.severityChange.restoreTitle', 'Restore the reported severity')
              : t('findings.severityChange.title', 'Change severity')}
          </DialogTitle>
          <DialogDescription>
            {t('findings.severityChange.description', 'From {from} to {to}.', {
              from: fromLabel,
              to: toLabel,
            })}{' '}
            {downgrade
              ? t(
                  'findings.severityChange.downgradeNote',
                  'Lowering a severity may need approval under your organization’s policy; until then the finding keeps its severity.'
                )
              : t(
                  'findings.severityChange.recomputeNote',
                  'Priority, SLA deadline and “Why it matters” are recomputed at once.'
                )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-2">
            <Label htmlFor="severity-reason">
              {t('findings.severityChange.reasonLabel', 'Reason (required)')}
            </Label>
            <Textarea
              id="severity-reason"
              value={reason}
              maxLength={SEVERITY_REASON_MAX}
              rows={3}
              placeholder={t(
                'findings.severityChange.reasonPlaceholder',
                'e.g. Only reachable from the build network; no customer data'
              )}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button disabled={!trimmed || busy} onClick={() => onConfirm(trimmed)}>
            {restore
              ? t('findings.severityChange.restoreConfirm', 'Restore')
              : t('findings.severityChange.confirm', 'Change severity')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
