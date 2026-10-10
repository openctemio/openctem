'use client'

/**
 * A scan's approval state on its page (RFC-073 §8): whether the
 * organization's rules hold it, the approval in force or the request
 * waiting, what changed since the last approval, Submit for approval, and
 * for owners and administrators an emergency run (a reason, 1 to 24 hours;
 * the API asks for re-authentication and audits it as critical). Nothing
 * shows while scan approval is Off.
 */

import { useId, useState } from 'react'
import { AlertTriangle, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  emergencyRunScan,
  submitScanApproval,
  useScanApprovalStatus,
} from '@/lib/api/scan-approval-hooks'
import { formatDateSafe } from '@/lib/format-date'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { ApprovalRequirement, approversText, missingEvidence } from './approval-requirement'

const HOURS = [1, 2, 4, 8, 12, 24]

export interface ScanApprovalPanelProps {
  scanId: string
  onRan?: () => void
}

export function ScanApprovalPanel({ scanId, onRan }: ScanApprovalPanelProps) {
  const { t } = useTranslation()
  const id = useId()
  const { isOwner, isAdmin } = usePermissions()
  const { data, mutate } = useScanApprovalStatus(scanId)
  const [submitOpen, setSubmitOpen] = useState(false)
  const [emergencyOpen, setEmergencyOpen] = useState(false)
  const [justification, setJustification] = useState('')
  const [ticket, setTicket] = useState('')
  const [runOnApproval, setRunOnApproval] = useState(true)
  const [reason, setReason] = useState('')
  const [hours, setHours] = useState('4')
  const [busy, setBusy] = useState(false)

  if (!data || data.mode === 'off') return null
  const ev = data.evaluation
  const current = data.current
  const pending = current?.status === 'pending'
  const canEmergency = (isOwner() || isAdmin()) && data.required && !data.approved
  const lacking = missingEvidence(t, ev, justification, ticket)

  const submit = async () => {
    setBusy(true)
    try {
      await submitScanApproval(scanId, { justification, ticket, run_on_approval: runOnApproval })
      toast.success(t('scans.approvalPanel.submitted', 'Submitted for approval'))
      setSubmitOpen(false)
      await mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, t('scans.approvalPanel.submitFailed', 'Could not submit')))
    } finally {
      setBusy(false)
    }
  }

  const emergency = async () => {
    setBusy(true)
    try {
      await emergencyRunScan(scanId, reason.trim(), Number(hours))
      toast.success(t('scans.approvalPanel.emergencyStarted', 'Emergency run started'))
      setEmergencyOpen(false)
      setReason('')
      await mutate()
      onRan?.()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('scans.approvalPanel.emergencyFailed', 'Could not start the emergency run')
        )
      )
    } finally {
      setBusy(false)
    }
  }

  let icon = <ShieldCheck className="size-5 text-success" aria-hidden />
  let title = t('scans.approvalPanel.notRequired', 'No approval needed')
  let detail = t(
    'scans.approvalPanel.notRequiredDetail',
    'No approval rule catches this scan as it is now.'
  )
  if (data.required && data.approved) {
    title = current?.emergency
      ? t('scans.approvalPanel.emergency', 'Emergency run window')
      : t('scans.approvalPanel.approved', 'Approved')
    detail = current?.valid_until
      ? t('scans.approvalPanel.validUntil', 'Runs are approved until {when}.', {
          when: formatDateSafe(current.valid_until, 'PPp'),
        })
      : t('scans.approvalPanel.validDefinition', 'Runs are approved until the scan changes.')
  } else if (data.required && pending) {
    icon = <ShieldQuestion className="size-5 text-warning" aria-hidden />
    title = t('scans.approvalPanel.pending', 'Waiting for approval')
    detail = t('scans.approvalPanel.pendingDetail', '{remaining} more approval(s) needed: {who}.', {
      remaining: current?.remaining ?? 0,
      who: approversText(t, ev),
    })
  } else if (data.required) {
    icon = <ShieldAlert className="size-5 text-destructive" aria-hidden />
    title = t('scans.approvalPanel.required', 'Needs approval before it runs')
    detail = t('scans.approvalPanel.requiredDetail', 'Needs approval by {who}.', {
      who: approversText(t, ev),
    })
  }

  return (
    <Card data-testid="scan-approval-panel">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          {icon}
          {title}
        </CardTitle>
        <CardDescription>{detail}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {(ev.matched ?? []).length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-xs text-muted-foreground">
              {t('scans.approvalPanel.caughtBy', 'Caught by')}
            </span>
            {(ev.matched ?? []).map((r) => (
              <Badge key={r.id} variant="outline">
                {r.name}
              </Badge>
            ))}
          </div>
        )}
        {data.changes.length > 0 && !data.approved && (
          <p className="text-xs text-muted-foreground">
            {t('scans.approvalPanel.changed', 'Changed since the last approval: {fields}.', {
              fields: data.changes.map((c) => c.field).join(', '),
            })}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          {data.required && !data.approved && !pending && (
            <Can permission={Permission.ScansWrite}>
              <Button size="sm" onClick={() => setSubmitOpen(true)}>
                {t('scans.approvalPanel.submit', 'Submit for approval')}
              </Button>
            </Can>
          )}
          {pending && (
            <Button size="sm" variant="outline" asChild>
              <Link href="/scans/approvals">
                {t('scans.approvalPanel.openInbox', 'Open approvals')}
              </Link>
            </Button>
          )}
          {canEmergency && (
            <Button size="sm" variant="outline" onClick={() => setEmergencyOpen(true)}>
              <AlertTriangle className="me-1.5 size-4" />
              {t('scans.approvalPanel.emergencyRun', 'Emergency run')}
            </Button>
          )}
        </div>
      </CardContent>

      <Dialog open={submitOpen} onOpenChange={(o) => !busy && setSubmitOpen(o)}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>{t('scans.approvalPanel.submit', 'Submit for approval')}</DialogTitle>
            <DialogDescription>{approversText(t, ev)}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <ApprovalRequirement
              evaluation={ev}
              justification={justification}
              ticket={ticket}
              onJustification={setJustification}
              onTicket={setTicket}
            />
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={runOnApproval} onCheckedChange={setRunOnApproval} />
              {t('scans.approvalPanel.runOnApproval', 'Run as soon as it is approved')}
            </label>
            {lacking && <p className="text-sm text-destructive">{lacking}</p>}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSubmitOpen(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button onClick={() => void submit()} disabled={busy || !!lacking}>
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
              {t('scans.approvalPanel.submit', 'Submit for approval')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={emergencyOpen} onOpenChange={(o) => !busy && setEmergencyOpen(o)}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>
              {t('scans.approvalPanel.emergencyTitle', 'Run without approval?')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'scans.approvalPanel.emergencyDesc',
                'An emergency run skips the approval for a limited time. You confirm your identity again; the run is audited as critical and the administrators are told.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor={`${id}-reason`}>{t('scans.approvalPanel.reason', 'Reason')}</Label>
              <Textarea
                id={`${id}-reason`}
                rows={3}
                maxLength={1000}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor={`${id}-hours`}>{t('scans.approvalPanel.window', 'Window')}</Label>
              <Select value={hours} onValueChange={setHours}>
                <SelectTrigger id={`${id}-hours`} className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {HOURS.map((h) => (
                    <SelectItem key={h} value={String(h)}>
                      {t('scans.approvalPanel.hours', '{count} hour(s)', { count: h })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEmergencyOpen(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() => void emergency()}
              disabled={busy || !reason.trim()}
            >
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
              {t('scans.approvalPanel.emergencyConfirm', 'Run now')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
