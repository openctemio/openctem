'use client'

/**
 * The break-glass dialog: let one commit of one repository pass the CI gate
 * for a limited time (api RFC-051). Opened from the gate settings (empty) or
 * from a failed run (repository and commit prefilled). The API requires the
 * CI override permission and a fresh step-up; this dialog is not the
 * authority.
 */

import { useEffect, useState } from 'react'
import { toast } from 'sonner'
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
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCreateGateOverride } from '../api/use-ci'

export interface CIOverrideDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Prefill (a failed run's repository and commit). */
  initialAssetId?: string
  initialSha?: string
  onCreated?: () => void
}

export function CIOverrideDialog({
  open,
  onOpenChange,
  initialAssetId = '',
  initialSha = '',
  onCreated,
}: CIOverrideDialogProps) {
  const { t } = useTranslation()
  const { trigger: create, isMutating } = useCreateGateOverride()
  const [assetId, setAssetId] = useState(initialAssetId)
  const [sha, setSha] = useState(initialSha)
  const [reason, setReason] = useState('')
  const [hours, setHours] = useState('24')

  // Each opening starts from the prefill, never from a previous draft.
  useEffect(() => {
    if (open) {
      setAssetId(initialAssetId)
      setSha(initialSha)
      setReason('')
      setHours('24')
    }
  }, [open, initialAssetId, initialSha])

  const hoursValue = Number(hours)
  const invalid =
    !assetId.trim() ||
    !/^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(sha.trim()) ||
    reason.trim().length < 10 ||
    !(hoursValue >= 1 && hoursValue <= 168)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('scans.ci.breakGlass.tab', 'Break-glass')}</DialogTitle>
          <DialogDescription>
            {t(
              'scans.ci.breakGlass.dialogDescription',
              'The commit passes the gate until the override expires or is revoked.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3">
            <Field label={t('scans.ci.repositoryAssetId', 'Repository asset ID')} id="ov-asset">
              <Input id="ov-asset" value={assetId} onChange={(e) => setAssetId(e.target.value)} />
            </Field>
            <Field
              label={t('scans.ci.breakGlass.commit', 'Commit')}
              id="ov-sha"
              hint={t(
                'scans.ci.breakGlass.commitHint',
                'The full commit id (40 characters). The override covers exactly this commit.'
              )}
            >
              <Input
                id="ov-sha"
                className="font-mono"
                value={sha}
                onChange={(e) => setSha(e.target.value)}
              />
            </Field>
            <Field
              label={t('scans.ci.breakGlass.reason', 'Reason')}
              id="ov-reason"
              hint={t(
                'scans.ci.breakGlass.reasonHint',
                'At least 10 characters; recorded in the audit log.'
              )}
            >
              <Textarea id="ov-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            </Field>
            <Field label={t('scans.ci.breakGlass.hours', 'Hours (1 to 168)')} id="ov-hours">
              <Input
                id="ov-hours"
                inputMode="numeric"
                value={hours}
                onChange={(e) => setHours(e.target.value)}
              />
            </Field>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            variant="destructive"
            disabled={invalid || isMutating}
            onClick={async () => {
              try {
                await create({
                  repository_asset_id: assetId.trim(),
                  commit_sha: sha.trim(),
                  reason: reason.trim(),
                  expires_in_hours: hoursValue,
                })
                toast.success(t('scans.ci.breakGlass.created', 'Override created'))
                onOpenChange(false)
                onCreated?.()
              } catch (e) {
                toast.error(getErrorMessage(e))
              }
            }}
          >
            {t('scans.ci.breakGlass.submit', 'Override the gate')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Field({
  label,
  id,
  hint,
  children,
}: {
  label: string
  id: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}
