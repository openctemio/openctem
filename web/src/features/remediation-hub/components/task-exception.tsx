'use client'

/**
 * A remediation task's group exception: the pending one (status, tier,
 * approvals so far, a link to the approvals inbox) or, when none is pending,
 * the action that asks for one. The API is the only authority; the UI only
 * hides what the caller could not do.
 */

import { useState } from 'react'
import { ShieldAlert, ShieldQuestion } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { RelativeTime } from '@/features/shared/components/relative-time'
import {
  usePendingTaskException,
  type ApprovalBatch,
} from '@/features/findings/api/use-approval-batches'
import { GroupExceptionDialog } from '@/features/findings/components/group-exception-dialog'
import { kindLabel, tierHelp, tierLabel } from '@/features/findings/lib/approval-policy'

/** The pending exception of a task, shown above its findings. */
export function PendingTaskException({ batch }: { batch: ApprovalBatch }) {
  const { t } = useTranslation()
  return (
    <div
      role="status"
      data-testid="task-pending-exception"
      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"
    >
      <ShieldAlert className="size-4 shrink-0 text-warning" aria-hidden />
      <span className="font-medium">
        {t('findingApprovals.group.pendingTitle', 'Exception pending: {kind}', {
          kind: kindLabel(t, batch.requested_status),
        })}
      </span>
      <Badge variant="outline" className="text-xs" title={tierHelp(t, batch.tier)}>
        {tierLabel(t, batch.tier)}
      </Badge>
      <span className="text-muted-foreground">
        {t('findings.approvals.progress', '{collected} of {required} approvals', {
          collected: batch.approvals_collected,
          required: batch.approvals_required,
        })}
      </span>
      <span className="text-muted-foreground">
        {t('findingApprovals.group.memberCount', '{count} finding(s)', {
          count: batch.member_count,
        })}
      </span>
      {batch.decide_by && (
        <span className="text-muted-foreground">
          {t('findingApprovals.group.decideBy', 'Decide by')}{' '}
          <RelativeTime date={batch.decide_by} />
        </span>
      )}
      <Link
        href={`/findings/approvals?view=groups&batch=${encodeURIComponent(batch.id)}`}
        className="ms-auto font-medium underline"
      >
        {t('findingApprovals.group.openInInbox', 'Open in approvals')}
      </Link>
    </div>
  )
}

/**
 * The pending exception banner and the "Request exception" action. `writable`
 * is the task page's own rule (open task, every finding visible, remediation
 * write); the request also needs findings:write.
 */
export function useTaskException(taskId: string, writable: boolean) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canRead = hasPermission(Permission.FindingsRead)
  const canRequest = writable && hasPermission(Permission.FindingsWrite)
  const { batch, mutate } = usePendingTaskException(taskId, canRead)
  const [open, setOpen] = useState(false)

  const action =
    canRequest && !batch ? (
      <Button variant="outline" onClick={() => setOpen(true)}>
        <ShieldQuestion className="size-4" aria-hidden />
        {t('findingApprovals.group.action', 'Request exception')}
      </Button>
    ) : null

  const banner = batch ? <PendingTaskException batch={batch} /> : null

  const dialog = canRequest ? (
    <GroupExceptionDialog
      taskId={taskId}
      open={open}
      onOpenChange={setOpen}
      onCreated={() => void mutate()}
      onPendingConflict={() => void mutate()}
    />
  ) : null

  return { action, banner, dialog, open }
}
