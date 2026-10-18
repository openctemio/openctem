'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Check, Info, Undo2, X } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import Link from '@/components/link'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataTable, ErrorState, PageHeader, RelativeTime, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import {
  approveAdminApproval,
  cancelAdminApproval,
  rejectAdminApproval,
  useAdminApprovals,
} from '@console/features/admin-console/api/use-admin-approvals'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@console/features/admin-console/components/admin-confirm-dialog'
import {
  approvalActionLabel,
  approvalTargetLabel,
} from '@console/features/admin-console/lib/approvals'
import { adminErrorMessage } from '@console/features/admin-console/components/totp-step-form'
import {
  adminCan,
  type AdminApproval,
  type AdminApprovalStatus,
} from '@console/features/admin-console/types'

const STATUS_VARIANT: Record<
  AdminApprovalStatus,
  'default' | 'secondary' | 'destructive' | 'outline'
> = {
  pending: 'default',
  approved: 'secondary',
  used: 'outline',
  rejected: 'destructive',
  canceled: 'outline',
  expired: 'outline',
}

const STATUS_FALLBACK: Record<AdminApprovalStatus, string> = {
  pending: 'Waiting',
  approved: 'Approved',
  used: 'Used',
  rejected: 'Rejected',
  canceled: 'Withdrawn',
  expired: 'Expired',
}

type Decision = { kind: 'approve' | 'reject'; approval: AdminApproval }

export default function AdminApprovalsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const isSuper = adminCan(admin.role, 'super_admin')
  const { data, error, isLoading, mutate } = useAdminApprovals(isSuper)
  const [deciding, setDeciding] = useState<Decision | null>(null)
  const canApprove = !!data?.four_eyes.can_approve

  const columns = useMemo<ColumnDef<AdminApproval>[]>(
    () => [
      {
        accessorKey: 'action',
        header: t('admin.approvals.col.action', 'Action'),
        cell: ({ row }) => (
          <StackedCell
            primary={approvalActionLabel(row.original.action, t)}
            secondary={approvalTargetLabel(row.original, t)}
          />
        ),
      },
      {
        accessorKey: 'requested_by_email',
        header: t('admin.approvals.col.requestedBy', 'Asked by'),
        cell: ({ row }) => (
          <div className="space-y-0.5 text-sm">
            <div>
              {row.original.mine
                ? t('admin.approvals.you', 'You')
                : row.original.requested_by_email || '-'}
            </div>
            <RelativeTime
              date={row.original.requested_at}
              className="text-xs text-muted-foreground"
            />
          </div>
        ),
      },
      {
        accessorKey: 'reason',
        header: t('admin.approvals.col.reason', 'Reason'),
        cell: ({ row }) => (
          <p className="max-w-xs whitespace-pre-wrap break-words text-sm">{row.original.reason}</p>
        ),
      },
      {
        accessorKey: 'status',
        header: t('admin.approvals.col.status', 'Status'),
        cell: ({ row }) => {
          const a = row.original
          return (
            <div className="space-y-0.5 text-sm">
              <Badge variant={STATUS_VARIANT[a.status] ?? 'outline'}>
                {t(`admin.approvals.status.${a.status}`, STATUS_FALLBACK[a.status] ?? a.status)}
              </Badge>
              {a.decided_by_email && (
                <div className="text-xs text-muted-foreground">
                  {t('admin.approvals.decidedBy', 'by {email}', { email: a.decided_by_email })}
                </div>
              )}
              {a.decision_note && (
                <div className="max-w-xs break-words text-xs text-muted-foreground">
                  {a.decision_note}
                </div>
              )}
              {(a.status === 'pending' || a.status === 'approved') && (
                <div className="text-xs text-muted-foreground">
                  {t('admin.approvals.expires', 'Expires')} <RelativeTime date={a.expires_at} />
                </div>
              )}
            </div>
          )
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => {
          const a = row.original
          if (a.status === 'approved' && a.mine)
            return (
              <span className="text-xs text-muted-foreground">
                {t('admin.approvals.repeat', 'Approved: repeat the action to use it.')}
              </span>
            )
          if (a.status !== 'pending') return null
          if (a.mine)
            return (
              <Button
                size="sm"
                variant="outline"
                onClick={async (e) => {
                  e.stopPropagation()
                  try {
                    await cancelAdminApproval(a.id)
                    toast.success(t('admin.approvals.canceled', 'Request withdrawn.'))
                    void mutate()
                  } catch (err) {
                    toast.error(
                      adminErrorMessage(
                        err,
                        t('admin.confirm.failed', 'The action failed. Try again.')
                      )
                    )
                  }
                }}
              >
                <Undo2 className="me-1 size-4" />
                {t('admin.approvals.cancel', 'Withdraw')}
              </Button>
            )
          return (
            <div className="flex flex-wrap gap-2">
              {canApprove && (
                <Button
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation()
                    setDeciding({ kind: 'approve', approval: a })
                  }}
                >
                  <Check className="me-1 size-4" />
                  {t('admin.approvals.approve', 'Approve')}
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation()
                  setDeciding({ kind: 'reject', approval: a })
                }}
              >
                <X className="me-1 size-4" />
                {t('admin.approvals.reject', 'Reject')}
              </Button>
            </div>
          )
        },
      },
    ],
    [t, canApprove, mutate]
  )

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.approvals', 'Approvals')}
        description={t(
          'admin.approvals.description',
          'Making or removing a super admin, turning off security keys, removing the administrators’ identity provider, opening sign-up and re-signing an audit chain need a second super admin. Approve only what you have checked with the person who asked.'
        )}
      />
      <div className="mt-5 space-y-4">
        {!isSuper ? (
          <p className="text-sm text-muted-foreground">
            {t('admin.approvals.superOnly', 'Only a super admin can see approvals.')}
          </p>
        ) : error ? (
          <ErrorState title="approvals" error={error} onRetry={() => void mutate()} />
        ) : (
          <>
            {data && !data.four_eyes.active && (
              <Alert>
                <Info className="size-4" />
                <AlertTitle>{t('admin.approvals.offTitle', 'Approvals are off')}</AlertTitle>
                <AlertDescription className="space-y-2">
                  <p>
                    {t(
                      'admin.approvals.offBody',
                      'No other super admin can approve, so these actions run on your confirmation alone. Each one is recorded as critical in the admin activity log and e-mailed to every administrator. Add a second named super admin to turn approvals on; break-glass accounts do not count, because their credentials are often held by the same people.'
                    )}
                  </p>
                  <Button asChild size="sm" variant="outline">
                    <Link href="/security/administrators">
                      {t('admin.approvals.addAdmin', 'Add a super admin')}
                    </Link>
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            {data && data.four_eyes.active && (
              <p className="text-sm text-muted-foreground">
                {t(
                  'admin.approvals.onBody',
                  '{count} super admins can approve. A request lasts {hours} hours; once approved, the person who asked repeats the action and the approval is used up.',
                  { count: data.four_eyes.approvers, hours: data.ttl_hours }
                )}
              </p>
            )}
            {data && !canApprove && (
              <p className="text-sm text-muted-foreground">
                {t(
                  'admin.approvals.breakGlassNote',
                  'This account is a break-glass account: it can ask and reject, but never approve.'
                )}
              </p>
            )}
            <DataTable
              columns={columns}
              data={data?.data ?? []}
              getRowId={(a) => a.id}
              isLoading={isLoading}
              showSearch={false}
              showColumnToggle={false}
              showSelectionCount={false}
              mobileCards
              emptyMessage={t('admin.approvals.empty', 'No requests in the last 30 days')}
            />
          </>
        )}
      </div>
      {deciding && (
        <AdminConfirmDialog
          open
          onOpenChange={(open) => !open && setDeciding(null)}
          title={
            deciding.kind === 'approve'
              ? t('admin.approvals.approveTitle', 'Approve this request')
              : t('admin.approvals.rejectTitle', 'Reject this request')
          }
          description={
            <p>
              {t(
                'admin.approvals.decideWhat',
                '{email} asks: {action} ({target}). Reason: {reason}',
                {
                  email: deciding.approval.requested_by_email || '-',
                  action: approvalActionLabel(deciding.approval.action, t),
                  target: approvalTargetLabel(deciding.approval, t),
                  reason: deciding.approval.reason,
                }
              )}
            </p>
          }
          confirmLabel={
            deciding.kind === 'approve'
              ? t('admin.approvals.approve', 'Approve')
              : t('admin.approvals.reject', 'Reject')
          }
          destructive={deciding.kind === 'reject'}
          onConfirm={async ({ reason }) => {
            if (deciding.kind === 'approve') {
              await approveAdminApproval(deciding.approval.id, reason)
              toast.success(
                t(
                  'admin.approvals.approved',
                  'Approved. The requester can now repeat the action once.'
                )
              )
            } else {
              await rejectAdminApproval(deciding.approval.id, reason)
              toast.success(t('admin.approvals.rejected', 'Request rejected.'))
            }
            void mutate()
          }}
        />
      )}
    </Main>
  )
}
