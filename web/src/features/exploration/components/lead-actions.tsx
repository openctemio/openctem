'use client'

/**
 * Approve and Dismiss for one or many exploration steps. Approving starts
 * active scanning, so the API asks for a recent step-up (the shared client
 * shows the step-up dialog and retries once). Dismiss asks for an optional
 * reason, kept in the audit log. Each lead is answered on its own: a lead
 * that changed meanwhile is reported, not hidden.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { approveLeads, dismissLeads, useRevalidateLeads } from '../hooks/use-leads'
import { bulkOutcome } from '../lib/leads'

const MAX_REASON = 500

export function useLeadActions(onDone?: () => void) {
  const { t } = useTranslation()
  const revalidate = useRevalidateLeads()
  const [busy, setBusy] = useState(false)
  const [dismissIds, setDismissIds] = useState<string[] | null>(null)

  const report = (results: Parameters<typeof bulkOutcome>[0], verb: 'approved' | 'dismissed') => {
    const { ok, failed } = bulkOutcome(results)
    if (ok > 0) {
      toast.success(
        verb === 'approved'
          ? t(
              'exploration.toast.approved',
              '{count, plural, one {# step approved} other {# steps approved}}',
              { count: ok }
            )
          : t(
              'exploration.toast.dismissed',
              '{count, plural, one {# step dismissed} other {# steps dismissed}}',
              { count: ok }
            )
      )
    }
    if (failed > 0) {
      toast.warning(
        t(
          'exploration.toast.someFailed',
          '{count, plural, one {# step was not changed: it changed meanwhile or is no longer waiting.} other {# steps were not changed: they changed meanwhile or are no longer waiting.}}',
          { count: failed }
        )
      )
    }
  }

  const approve = async (ids: string[]) => {
    if (ids.length === 0) return
    setBusy(true)
    try {
      const res = await approveLeads(ids)
      report(res.results, 'approved')
      onDone?.()
    } catch (e) {
      toast.error(getErrorMessage(e, t('exploration.toast.approveFailed', 'Could not approve')))
    } finally {
      setBusy(false)
      void revalidate()
    }
  }

  const dismiss = async (ids: string[], reason: string) => {
    setBusy(true)
    try {
      const res = await dismissLeads(ids, reason.trim() || undefined)
      report(res.results, 'dismissed')
      setDismissIds(null)
      onDone?.()
    } catch (e) {
      toast.error(getErrorMessage(e, t('exploration.toast.dismissFailed', 'Could not dismiss')))
    } finally {
      setBusy(false)
      void revalidate()
    }
  }

  const dialog = (
    <DismissDialog
      ids={dismissIds}
      busy={busy}
      onOpenChange={(open) => !open && setDismissIds(null)}
      onConfirm={dismiss}
    />
  )

  return { busy, approve, askDismiss: setDismissIds, dialog }
}

function DismissDialog({
  ids,
  busy,
  onOpenChange,
  onConfirm,
}: {
  ids: string[] | null
  busy: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (ids: string[], reason: string) => void
}) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const count = ids?.length ?? 0
  return (
    <Dialog
      open={!!ids}
      onOpenChange={(open) => {
        if (!open) setReason('')
        onOpenChange(open)
      }}
    >
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t(
              'exploration.dismiss.title',
              '{count, plural, one {Dismiss # step?} other {Dismiss # steps?}}',
              { count }
            )}
          </DialogTitle>
          <DialogDescription>
            {t(
              'exploration.dismiss.desc',
              'Nothing more runs for a dismissed step; a running step settles from its run. The reason is kept in the audit log.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            if (ids) onConfirm(ids, reason)
          }}
        >
          <DialogBody className="space-y-2">
            <Label htmlFor="exploration-dismiss-reason">
              {t('exploration.dismiss.reason', 'Reason (optional)')}
            </Label>
            <Textarea
              id="exploration-dismiss-reason"
              value={reason}
              maxLength={MAX_REASON}
              onChange={(e) => setReason(e.target.value)}
            />
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy || count === 0}>
              {t('exploration.actions.dismiss', 'Dismiss')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
