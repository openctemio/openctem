'use client'

/**
 * The verification queue's group actions: approve or reject every claimed fix
 * of a CVE. The queue itself is the grouped findings table (group by CVE,
 * status fix_applied) on the Findings page.
 */

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { CheckCircle, XCircle, Loader2 } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogBody,
} from '@/components/ui/alert-dialog'
import { Textarea } from '@/components/ui/textarea'
import { toast } from 'sonner'
import { post } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { FindingGroup } from '../api/use-finding-groups'

interface VerifyGroupActionsProps {
  /** A CVE group; every claimed fix of its CVE is approved or rejected. */
  group?: FindingGroup
  /** Or one finding with no CVE: only that finding is approved or rejected. */
  finding?: { id: string; title: string }
  /** Called after the group's fixes were approved or rejected. */
  onDone?: () => void
}

/** Approve / Reject for one CVE group in the verification queue. */
export function VerifyGroupActions({ group, finding, onDone }: VerifyGroupActionsProps) {
  const { t } = useTranslation()
  const key = finding?.id ?? group?.group_key ?? ''
  const label = finding?.title ?? group?.label ?? ''
  const count = finding ? 1 : (group?.stats?.fix_applied ?? 0)
  // One finding goes by its id; a CVE group by its CVE.
  const target = finding ? { finding_ids: [finding.id] } : { filter: { cve_ids: [key] } }
  const [busy, setBusy] = useState(false)
  const [rejectOpen, setRejectOpen] = useState(false)
  const [reason, setReason] = useState('')

  const approve = async () => {
    setBusy(true)
    try {
      const result = await post<{ updated: number }>('/api/v1/findings/actions/verify', {
        ...target,
        note: `Batch verified: ${label}`,
      })
      toast.success(
        t('findings.verifyGroup.verified', '{count} findings verified', { count: result.updated })
      )
      onDone?.()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.verifyGroup.verifyFailed', 'Failed to verify findings'))
      )
    } finally {
      setBusy(false)
    }
  }

  const reject = async () => {
    if (!reason.trim()) return
    setBusy(true)
    try {
      const result = await post<{ updated: number }>('/api/v1/findings/actions/reject-fix', {
        ...target,
        reason: reason.trim(),
      })
      toast.success(
        t('findings.verifyGroup.rejected', '{count} findings rejected, sent back to the assignee', {
          count: result.updated,
        })
      )
      setRejectOpen(false)
      setReason('')
      onDone?.()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.verifyGroup.rejectFailed', 'Failed to reject fix'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button variant="outline" size="sm" className="h-7 px-2" onClick={approve} disabled={busy}>
        {busy ? (
          <Loader2 className="me-1 h-3.5 w-3.5 animate-spin" />
        ) : (
          <CheckCircle className="me-1 h-3.5 w-3.5 text-success" />
        )}
        {t('findings.verifyGroup.approve', 'Approve')}
      </Button>
      <Button
        variant="outline"
        size="sm"
        className="h-7 px-2"
        onClick={() => setRejectOpen(true)}
        disabled={busy}
      >
        <XCircle className="me-1 h-3.5 w-3.5 text-destructive" />
        {t('findings.verifyGroup.reject', 'Reject')}
      </Button>

      <AlertDialog open={rejectOpen} onOpenChange={setRejectOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('findings.verifyGroup.rejectFix', 'Reject fix')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'findings.verifyGroup.rejectDesc',
                'The findings go back to the assignee as In progress. Say why the fix is not enough.'
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogBody className="grid gap-4">
            <div className="my-2 rounded-lg border bg-muted/50 p-3">
              <p className="font-medium">{label}</p>
              <p className="text-sm text-muted-foreground">
                {t('findings.verifyGroup.reopened', '{count} findings will be reopened', {
                  count,
                })}
              </p>
            </div>
            <div className="space-y-2">
              <label htmlFor={`reject-${key}`} className="text-sm font-medium">
                {t('findings.verifyGroup.reason', 'Reason')}
              </label>
              <Textarea
                id={`reject-${key}`}
                placeholder={t(
                  'findings.verifyGroup.reasonPlaceholder',
                  'e.g. Vulnerability still present: log4j 2.14.0 detected on server'
                )}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={3}
              />
            </div>
          </AlertDialogBody>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel', 'Cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void reject()
              }}
              disabled={!reason.trim() || busy}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {t('findings.verifyGroup.rejectFix', 'Reject fix')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
