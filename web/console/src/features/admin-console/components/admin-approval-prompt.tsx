'use client'

import { useEffect, useState } from 'react'
import { Hourglass } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
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
import { setAdminApprovalPrompt, type AdminApprovalNeeded } from '@console/lib/admin-api/client'
import { requestAdminApproval } from '../api/use-admin-approvals'
import { approvalActionLabel, approvalTargetLabel } from '../lib/approvals'
import { AdminConfirmDialog } from './admin-confirm-dialog'

/** Security > Approvals. */
export const APPROVALS_PATH = '/security/approvals'

/**
 * The console's one four-eyes dialog. A catastrophic action refused with
 * SECOND_APPROVAL_REQUIRED opens it: the administrator asks another super
 * admin with a reason, or sees that their request is still waiting. After the
 * approval they repeat the action, which spends it. Mounted once by the
 * console shell.
 */
export function AdminApprovalPrompt() {
  const { t } = useTranslation()
  const [needed, setNeeded] = useState<AdminApprovalNeeded | null>(null)

  useEffect(() => {
    setAdminApprovalPrompt((n) => setNeeded(n))
    return () => setAdminApprovalPrompt(null)
  }, [])

  if (!needed) return null
  const what = (
    <p>
      {t(
        'admin.approvals.prompt.what',
        '{action}: {target}. Another super admin must approve this before it runs. When they have, repeat the action within 24 hours; the approval works once.',
        {
          action: approvalActionLabel(needed.action, t),
          target: approvalTargetLabel(needed, t),
        }
      )}
    </p>
  )

  if (needed.pending_approval_id) {
    return (
      <Dialog open onOpenChange={(open) => !open && setNeeded(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Hourglass className="size-5" />
              {t('admin.approvals.prompt.waitingTitle', 'Waiting for approval')}
            </DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-2 text-sm text-muted-foreground">
                {what}
                <p>
                  {t(
                    'admin.approvals.prompt.waiting',
                    'You already asked. The other super admins were e-mailed; the request is under Security > Approvals.'
                  )}
                </p>
              </div>
            </DialogDescription>
          </DialogHeader>
          <DialogBody />
          <DialogFooter>
            <Button variant="outline" onClick={() => setNeeded(null)}>
              {t('admin.approvals.close', 'Close')}
            </Button>
            <Button asChild onClick={() => setNeeded(null)}>
              <Link href={APPROVALS_PATH}>
                {t('admin.approvals.prompt.open', 'Open approvals')}
              </Link>
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <AdminConfirmDialog
      open
      onOpenChange={(open) => !open && setNeeded(null)}
      title={t('admin.approvals.prompt.title', 'Another super admin must approve')}
      description={what}
      confirmLabel={t('admin.approvals.prompt.ask', 'Ask for approval')}
      onConfirm={async ({ reason }) => {
        await requestAdminApproval({ action: needed.action, target: needed.target, reason })
        toast.success(
          t(
            'admin.approvals.prompt.asked',
            'Approval requested. The other super admins were e-mailed. Repeat the action once one of them approves.'
          )
        )
      }}
    />
  )
}
