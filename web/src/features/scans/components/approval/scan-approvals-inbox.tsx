'use client'

/**
 * Scans > Approvals: the scan approval requests of the organization
 * (RFC-072). Approvers see what each scan will do (targets, intensity,
 * tools, schedule, the rule that caught it and what changed since the last
 * approval) and approve or reject it; requesters remind or withdraw. The
 * backend decides who may act: these buttons only follow `can_approve` and
 * `self_approval_available`.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { CheckCheck, ChevronDown, ChevronRight, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatRelative } from '@/lib/format-date'
import {
  approveScanRequest,
  cancelScanRequest,
  rejectScanRequest,
  remindScanApprovers,
  selfApproveScanRequest,
  useScanApprovals,
  type ScanApprovalRequest,
} from '@/lib/api/scan-approval-hooks'
import { useAuthStore } from '@/stores/auth-store'
import { approversText } from './approval-requirement'

type Action = 'approve' | 'reject' | 'self'

const PREVIEW_TARGETS = 10

function formatValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '—'
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function RequestDetails({ req }: { req: ScanApprovalRequest }) {
  const { t } = useTranslation()
  const targets = req.definition.targets ?? []
  const groups = req.definition.asset_group_ids ?? []
  return (
    <div className="grid gap-3 border-t bg-muted/30 p-4 text-sm md:grid-cols-2">
      <div className="space-y-1">
        <p className="font-medium">{t('scans.approval.targets', 'Targets')}</p>
        <p className="text-muted-foreground">
          {t('scans.approval.targetsCount', '{targets} targets, {groups} asset groups', {
            targets: targets.length,
            groups: groups.length,
          })}
        </p>
        <ul className="font-mono text-xs">
          {targets.slice(0, PREVIEW_TARGETS).map((x) => (
            <li key={x}>{x}</li>
          ))}
          {targets.length > PREVIEW_TARGETS && (
            <li className="text-muted-foreground">
              {t('scans.approval.moreTargets', '+{count} more', {
                count: targets.length - PREVIEW_TARGETS,
              })}
            </li>
          )}
        </ul>
      </div>
      <div className="space-y-1">
        <p className="font-medium">{t('scans.approval.what', 'What runs')}</p>
        <p className="text-muted-foreground">
          {req.definition.scanner_name ||
            (req.definition.workflow_steps ?? []).join(', ') ||
            req.definition.scan_type}
          {' · '}
          {t('scans.approval.schedule', 'schedule: {value}', {
            value: req.definition.schedule_type ?? '—',
          })}
        </p>
        {req.justification && (
          <p>
            <span className="font-medium">
              {t('scans.approval.justification', 'Justification')}:
            </span>{' '}
            {req.justification}
          </p>
        )}
        {req.ticket && (
          <p>
            <span className="font-medium">{t('scans.approval.ticket', 'Change ticket')}:</span>{' '}
            {req.ticket}
          </p>
        )}
        {req.decision_note && (
          <p>
            <span className="font-medium">{t('scans.approval.decisionNote', 'Note')}:</span>{' '}
            {req.decision_note}
          </p>
        )}
      </div>
      {req.changes.length > 0 && (
        <div className="space-y-1 md:col-span-2">
          <p className="font-medium">
            {t('scans.approval.changes', 'Changed since the last approval')}
          </p>
          <ul className="space-y-1 text-xs">
            {req.changes.map((c) => (
              <li key={c.field} className="grid gap-1 sm:grid-cols-[10rem_1fr]">
                <span className="font-mono">{c.field}</span>
                <span>
                  <span className="text-muted-foreground line-through">
                    {formatValue(c.before)}
                  </span>
                  {' → '}
                  <span>{formatValue(c.after)}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: ScanApprovalRequest['status'] }) {
  const { t } = useTranslation()
  const label: Record<ScanApprovalRequest['status'], string> = {
    pending: t('scans.approval.statusPending', 'Awaiting approval'),
    approved: t('scans.approval.statusApproved', 'Approved'),
    rejected: t('scans.approval.statusRejected', 'Rejected'),
    expired: t('scans.approval.statusExpired', 'Expired'),
    superseded: t('scans.approval.statusSuperseded', 'Superseded'),
    canceled: t('scans.approval.statusCanceled', 'Withdrawn'),
  }
  const variant = status === 'pending' ? 'secondary' : status === 'approved' ? 'default' : 'outline'
  return <Badge variant={variant}>{label[status]}</Badge>
}

export function ScanApprovalsInbox() {
  const { t } = useTranslation()
  const me = useAuthStore((s) => s.user?.id)
  const [filter, setFilter] = useState<'pending' | 'all'>('pending')
  const { data, error, isLoading, mutate } = useScanApprovals(filter === 'pending' ? 'pending' : '')
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const [action, setAction] = useState<{ kind: Action; req: ScanApprovalRequest } | null>(null)
  const [note, setNote] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    try {
      await fn()
      toast.success(ok)
      setAction(null)
      setNote('')
      setCode('')
      await mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, t('scans.approval.actionFailed', 'The action failed')))
    } finally {
      setBusy(false)
    }
  }

  const confirm = () => {
    if (!action) return
    const { kind, req } = action
    if (kind === 'approve') {
      void run(
        () => approveScanRequest(req.id, note),
        t('scans.approval.approvedToast', 'Approval recorded')
      )
    } else if (kind === 'reject') {
      void run(
        () => rejectScanRequest(req.id, note),
        t('scans.approval.rejectedToast', 'Request rejected')
      )
    } else {
      void run(
        () => selfApproveScanRequest(req.id, note, code),
        t('scans.approval.selfApprovedToast', 'Approved with your authenticator code')
      )
    }
  }

  const items = data?.data ?? []

  return (
    <div className="mt-5 space-y-4">
      <div className="flex gap-2" role="group" aria-label={t('scans.approval.filter', 'Filter')}>
        <Button
          size="sm"
          variant={filter === 'pending' ? 'default' : 'outline'}
          onClick={() => setFilter('pending')}
        >
          {t('scans.approval.filterPending', 'Awaiting approval')}
        </Button>
        <Button
          size="sm"
          variant={filter === 'all' ? 'default' : 'outline'}
          onClick={() => setFilter('all')}
        >
          {t('scans.approval.filterAll', 'All requests')}
        </Button>
      </div>

      {error ? (
        <ErrorState
          title={t('scans.approval.errorTitle', 'scan approvals')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-48 w-full" />
      ) : items.length === 0 ? (
        <EmptyState
          icon={CheckCheck}
          title={t('scans.approval.emptyTitle', 'No scan waits for approval')}
          description={t(
            'scans.approval.emptyDesc',
            'Scans the organization’s approval rules catch appear here when someone submits them.'
          )}
        />
      ) : (
        <ul className="divide-y rounded-md border" data-testid="scan-approvals">
          {items.map((req) => {
            const expanded = !!open[req.id]
            const mine = req.requested_by?.id === me
            const pending = req.status === 'pending'
            return (
              <li key={req.id}>
                <div className="flex flex-wrap items-center gap-3 p-3">
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-expanded={expanded}
                    aria-label={t('scans.approval.toggleDetails', 'Show details')}
                    onClick={() => setOpen((o) => ({ ...o, [req.id]: !expanded }))}
                  >
                    {expanded ? (
                      <ChevronDown className="size-4" />
                    ) : (
                      <ChevronRight className="size-4" />
                    )}
                  </Button>
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link href={`/scans/${req.scan_id}`} className="font-medium hover:underline">
                        {req.scan_name || req.scan_id}
                      </Link>
                      <StatusBadge status={req.status} />
                      {req.emergency && (
                        <Badge variant="destructive">
                          {t('scans.approval.emergency', 'Emergency run')}
                        </Badge>
                      )}
                      {req.definition.intensity && (
                        <Badge variant="outline">{req.definition.intensity}</Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {t('scans.approval.requestedBy', 'Requested by {name} {when}', {
                        name: req.requested_by?.name ?? '—',
                        when: formatRelative(req.requested_at),
                      })}
                      {' · '}
                      {(req.evaluation.matched ?? []).map((r) => r.name).join(', ')}
                    </p>
                    {pending && (
                      <p className="text-xs text-muted-foreground">
                        {t('scans.approval.remaining', '{count} approval(s) left · {who}', {
                          count: req.remaining,
                          who: approversText(t, req.evaluation),
                        })}
                      </p>
                    )}
                  </div>
                  {pending && (
                    <div className="flex flex-wrap gap-2">
                      {req.can_approve && (
                        <>
                          <Button size="sm" onClick={() => setAction({ kind: 'approve', req })}>
                            {t('scans.approval.approve', 'Approve')}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setAction({ kind: 'reject', req })}
                          >
                            {t('scans.approval.reject', 'Reject')}
                          </Button>
                        </>
                      )}
                      {req.self_approval_available && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setAction({ kind: 'self', req })}
                        >
                          <ShieldCheck className="me-1 size-4" />
                          {t('scans.approval.selfApprove', 'Approve my own scan')}
                        </Button>
                      )}
                      {mine && (
                        <>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void run(
                                () => remindScanApprovers(req.id),
                                t('scans.approval.remindedToast', 'Approvers reminded')
                              )
                            }
                          >
                            {t('scans.approval.remind', 'Remind')}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void run(
                                () => cancelScanRequest(req.id),
                                t('scans.approval.canceledToast', 'Request withdrawn')
                              )
                            }
                          >
                            {t('scans.approval.withdraw', 'Withdraw')}
                          </Button>
                        </>
                      )}
                    </div>
                  )}
                </div>
                {expanded && <RequestDetails req={req} />}
              </li>
            )
          })}
        </ul>
      )}

      <Dialog open={!!action} onOpenChange={(o) => !busy && !o && setAction(null)}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>
              {action?.kind === 'reject'
                ? t('scans.approval.rejectTitle', 'Reject this scan?')
                : action?.kind === 'self'
                  ? t('scans.approval.selfTitle', 'Approve your own scan?')
                  : t('scans.approval.approveTitle', 'Approve this scan?')}
            </DialogTitle>
            <DialogDescription>
              {action?.kind === 'self'
                ? t(
                    'scans.approval.selfDesc',
                    'No other approver can approve it. Confirm with a code from your authenticator and say why; every administrator is told.'
                  )
                : (action?.req.scan_name ?? '')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="approval-note">
                {action?.kind === 'self'
                  ? t('scans.approval.reason', 'Reason')
                  : t('scans.approval.noteOptional', 'Note (optional)')}
              </Label>
              <Textarea
                id="approval-note"
                rows={2}
                maxLength={1000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
            {action?.kind === 'self' && (
              <div className="space-y-1">
                <Label htmlFor="approval-code">
                  {t('scans.approval.code', 'Code from your authenticator')}
                </Label>
                <Input
                  id="approval-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={8}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </div>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAction(null)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={confirm}
              disabled={
                busy || (action?.kind === 'self' && (!note.trim() || code.trim().length < 6))
              }
              variant={action?.kind === 'reject' ? 'destructive' : 'default'}
            >
              {action?.kind === 'reject'
                ? t('scans.approval.reject', 'Reject')
                : t('scans.approval.approve', 'Approve')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
