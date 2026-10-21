'use client'

/**
 * An owner approves their own pending scope entry when nobody else can
 * (RFC-054 §7): an organization with a single owner. The API decides
 * whether it is allowed (`approval.self_approval_available`); the dialog
 * asks for a reason and a fresh code from the owner's authenticator app. It
 * is audited at high severity and every administrator is told.
 */

import { useId, useState } from 'react'
import { toast } from 'sonner'
import { StepUpDialog } from '@/components/security'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { invalidateScopeCache, selfApproveScopeTarget } from '../api/use-scope-api'
import type { ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'

interface ScopeSelfApproveDialogProps {
  entry: ApiScopeTarget | null
  onOpenChange: (open: boolean) => void
}

export function ScopeSelfApproveDialog({ entry, onOpenChange }: ScopeSelfApproveDialogProps) {
  const { t } = useTranslation()
  const reasonId = useId()
  const [reason, setReason] = useState('')

  if (!entry) return null

  return (
    <StepUpDialog
      open
      onOpenChange={onOpenChange}
      title={t('scope.selfApprove.title', 'Approve your own entry')}
      description={t(
        'scope.selfApprove.description',
        'Nobody else in your organization can approve {pattern}. As an owner you may approve it yourself. This is recorded in the audit log and every administrator is told.',
        { pattern: entry.pattern ?? '' }
      )}
      ready={!!reason.trim()}
      submitLabel={t('scope.selfApprove.submit', 'Approve')}
      onSubmit={async (proof) => {
        if (proof.kind !== 'totp') return
        await selfApproveScopeTarget(entry.id ?? '', {
          reason: reason.trim(),
          totp_code: proof.code,
        })
        await invalidateScopeCache()
        toast.success(
          t('scope.selfApprove.done', '{pattern} is in effect', { pattern: entry.pattern ?? '' })
        )
        onOpenChange(false)
      }}
      errorMessage={(err) =>
        scopeErrorMessage(t, err, t('scope.selfApprove.failed', 'Could not approve the entry.'))
      }
    >
      <div className="space-y-2">
        <Label htmlFor={reasonId}>
          {t('scope.selfApprove.reason', 'Why may it take effect without a second person?')}
        </Label>
        <Textarea
          id={reasonId}
          rows={3}
          maxLength={1000}
          required
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      </div>
    </StepUpDialog>
  )
}
