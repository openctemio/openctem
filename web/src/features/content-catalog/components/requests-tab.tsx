'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import type { ContentInstallRequest } from '@/lib/api/generated'
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
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ActorChip, DataTable, ErrorState, RelativeTime, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { useAuthStore } from '@/stores/auth-store'
import { cancelRequest, decideRequest, useContentRequests } from '../api'
import { requestActions, sortRequests } from '../lib'

const REASON_MAX = 500

type Decision = { req: ContentInstallRequest; kind: 'approve' | 'reject' }

const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  pending: 'default',
  approved: 'secondary',
  rejected: 'destructive',
  failed: 'destructive',
  canceled: 'outline',
}

function DecisionDialog({
  decision,
  onClose,
  onDone,
}: {
  decision: Decision
  onClose: () => void
  onDone: () => void
}) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const approve = decision.kind === 'approve'
  const id = `content-decision-reason-${decision.kind}`

  async function submit() {
    if (!decision.req.id) return
    setBusy(true)
    setError(null)
    try {
      await decideRequest(decision.req.id, decision.kind, reason.trim().slice(0, REASON_MAX))
      toast.success(
        approve
          ? t('contentCatalog.request.approved', 'Request approved')
          : t('contentCatalog.request.rejected', 'Request rejected')
      )
      onDone()
      onClose()
    } catch (err) {
      setError(getErrorMessage(err, t('contentCatalog.error.generic', 'The change was refused.')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle className="break-all">
            {approve
              ? t('contentCatalog.request.approveTitle', 'Approve the request for {id}', {
                  id: decision.req.package_id ?? '',
                })
              : t('contentCatalog.request.rejectTitle', 'Reject the request for {id}', {
                  id: decision.req.package_id ?? '',
                })}
          </DialogTitle>
          <DialogDescription>
            {approve
              ? t(
                  'contentCatalog.request.approveDesc',
                  'The change is applied for the whole organization as soon as you approve it.'
                )
              : t('contentCatalog.request.rejectDesc', 'Nothing changes; the requester sees why.')}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-1.5">
          <Label htmlFor={id}>{t('contentCatalog.field.reason', 'Reason')}</Label>
          <Textarea
            id={id}
            value={reason}
            maxLength={REASON_MAX}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
          />
          {error && (
            <p role="alert" className="text-sm break-words text-destructive">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('contentCatalog.cancel', 'Cancel')}
          </Button>
          <Button
            variant={approve ? 'default' : 'destructive'}
            onClick={() => void submit()}
            disabled={busy || (!approve && !reason.trim())}
          >
            {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
            {approve
              ? t('contentCatalog.request.approve', 'Approve')
              : t('contentCatalog.request.reject', 'Reject')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Changes waiting for a second member, pending first; approve, reject or cancel your own. */
export function RequestsTab({
  onOpen,
  onChanged,
}: {
  onOpen: (packageId: string) => void
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canInstall = can(Permission.ContentInstall)
  const userId = useAuthStore((s) => s.user?.id)
  const requests = useContentRequests()
  const [decision, setDecision] = useState<Decision | null>(null)
  const [canceling, setCanceling] = useState<string | null>(null)
  const rows = useMemo(() => sortRequests(requests.data ?? []), [requests.data])

  const columns = useMemo<ColumnDef<ContentInstallRequest>[]>(() => {
    const refresh = () => {
      void requests.mutate()
      onChanged()
    }
    async function cancel(req: ContentInstallRequest) {
      if (!req.id) return
      setCanceling(req.id)
      try {
        await cancelRequest(req.id)
        toast.success(t('contentCatalog.request.canceled', 'Request canceled'))
        refresh()
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('contentCatalog.error.generic', 'The change was refused.'))
        )
      } finally {
        setCanceling(null)
      }
    }
    return [
      {
        id: 'package',
        header: t('contentCatalog.col.package', 'Package'),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.package_id}
            secondary={[
              t(`contentCatalog.requestAction.${row.original.action}`, row.original.action ?? ''),
              row.original.target?.version,
            ]
              .filter(Boolean)
              .join(' ')}
          />
        ),
      },
      {
        id: 'status',
        header: t('contentCatalog.col.status', 'Status'),
        cell: ({ row }) => (
          <Badge variant={STATUS_VARIANT[row.original.status ?? ''] ?? 'outline'}>
            {t(`contentCatalog.requestStatus.${row.original.status}`, row.original.status ?? '')}
          </Badge>
        ),
      },
      {
        id: 'requested',
        header: t('contentCatalog.col.requestedBy', 'Requested by'),
        cell: ({ row }) => (
          <div className="space-y-0.5">
            <ActorChip actor={row.original.requested_by} at={row.original.created_at} compact />
            {row.original.note && (
              <p className="max-w-xs text-xs break-words text-muted-foreground">
                {row.original.note}
              </p>
            )}
          </div>
        ),
      },
      {
        id: 'decision',
        header: t('contentCatalog.col.decision', 'Decision'),
        cell: ({ row }) =>
          row.original.decided_at ? (
            <div className="space-y-0.5 text-sm">
              <RelativeTime date={row.original.decided_at} />
              {row.original.decision_reason && (
                <p className="max-w-xs text-xs break-words text-muted-foreground">
                  {row.original.decision_reason}
                </p>
              )}
            </div>
          ) : (
            <span className="text-sm text-muted-foreground">-</span>
          ),
      },
      {
        id: 'actions',
        header: () => <span className="sr-only">{t('contentCatalog.col.actions', 'Actions')}</span>,
        cell: ({ row }) => {
          const req = row.original
          const a = requestActions(req, userId, canInstall)
          if (!a.decide && !a.cancel) return null
          return (
            // Buttons act on the request; keep the row click (open the package) off them.
            <div
              className="flex flex-wrap justify-end gap-1.5"
              onClick={(e) => e.stopPropagation()}
              onKeyDown={(e) => e.stopPropagation()}
              role="presentation"
            >
              {a.decide && (
                <>
                  <Button size="sm" onClick={() => setDecision({ req, kind: 'approve' })}>
                    {t('contentCatalog.request.approve', 'Approve')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setDecision({ req, kind: 'reject' })}
                  >
                    {t('contentCatalog.request.reject', 'Reject')}
                  </Button>
                </>
              )}
              {a.cancel && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={canceling === req.id}
                  onClick={() => void cancel(req)}
                >
                  {canceling === req.id && <Loader2 className="size-4 animate-spin" aria-hidden />}
                  {t('contentCatalog.request.cancel', 'Cancel request')}
                </Button>
              )}
            </div>
          )
        },
      },
    ]
  }, [t, userId, canInstall, canceling, requests, onChanged])

  if (requests.error) {
    return (
      <ErrorState
        title={t('contentCatalog.requestsWhat', 'the requests')}
        error={requests.error}
        onRetry={() => void requests.mutate()}
      />
    )
  }

  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        getRowId={(r) => r.id ?? ''}
        isLoading={requests.isLoading}
        showSearch={false}
        showColumnToggle={false}
        showSelectionCount={false}
        mobileCards
        onRowClick={(r) => r.package_id && onOpen(r.package_id)}
        emptyMessage={t('contentCatalog.emptyRequests', 'No requests')}
      />
      {decision && (
        <DecisionDialog
          key={`${decision.kind}-${decision.req.id}`}
          decision={decision}
          onClose={() => setDecision(null)}
          onDone={() => {
            void requests.mutate()
            onChanged()
          }}
        />
      )}
    </>
  )
}
