'use client'

/**
 * Change an exposure's severity as an analyst decision, or go back to the
 * reported severity. A reason is always required and the change is audited;
 * the reported severity stays visible. Shown only to holders of
 * findings:severity and exposures triage (the API is the authority).
 */

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
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
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { FilterSelect, SeverityBadge } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { SEVERITY_LEVELS, SEVERITY_LABELS } from '@/lib/severity'
import type { ExposureEvent, ExposureSeverity } from '@/lib/api/exposure-types'
import { changeExposureSeverity } from '../hooks/use-exposures'

/** The API's bound on a reason. */
export const SEVERITY_REASON_MAX = 1000

/** Whether the viewer may change an exposure's severity. */
export function useCanChangeExposureSeverity(): boolean {
  const severity = useHasPermission(Permission.FindingsSeverity)
  const triage = useHasPermission(Permission.ExposuresTriage)
  return severity && triage
}

interface ExposureSeverityDialogProps {
  exposure: ExposureEvent | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

export function ExposureSeverityDialog({
  exposure,
  open,
  onOpenChange,
  onSuccess,
}: ExposureSeverityDialogProps) {
  const { t } = useTranslation()
  const [severity, setSeverity] = useState<ExposureSeverity | ''>('')
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  if (!exposure) return null
  const override = exposure.severity_override
  const reported = override?.reported_severity ?? exposure.severity
  const target = severity || exposure.severity
  const label = (s: ExposureSeverity) => t(`severity.${s}`, SEVERITY_LABELS[s])

  const close = () => {
    setSeverity('')
    setReason('')
    onOpenChange(false)
  }

  const submit = async (restore: boolean) => {
    const r = reason.trim()
    if (!r) return
    setSaving(true)
    try {
      await changeExposureSeverity(exposure.id, { severity: restore ? '' : target, reason: r })
      toast.success(
        restore
          ? t('exposures.severity.restored', 'The reported severity applies again')
          : t('exposures.severity.changed', 'Severity changed')
      )
      close()
      onSuccess?.()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('exposures.severity.failed', 'Could not change the severity'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('exposures.severity.title', 'Change severity')}</DialogTitle>
          <DialogDescription>
            {t(
              'exposures.severity.description',
              'Set the severity your team works with. The severity the scan reported stays recorded, later scans do not change your decision, and the change is audited.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <p className="text-sm font-medium">{exposure.title}</p>
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <span>{t('exposures.severity.reported', 'Reported by the scan')}</span>
            <SeverityBadge severity={reported} />
          </div>
          <FilterSelect<ExposureSeverity>
            label={t('exposures.severity.new', 'New severity')}
            value={target}
            options={SEVERITY_LEVELS.map((s) => ({ value: s, label: label(s) }))}
            onChange={(v) => setSeverity(v || '')}
            clearable={false}
          />
          <div className="space-y-2">
            <Label htmlFor="exposure-severity-reason">
              {t('exposures.severity.reason', 'Reason (required)')}
            </Label>
            <Textarea
              id="exposure-severity-reason"
              value={reason}
              maxLength={SEVERITY_REASON_MAX}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t(
                'exposures.severity.reasonPlaceholder',
                'For example: only reachable over the VPN'
              )}
              rows={3}
            />
          </div>
        </DialogBody>
        <DialogFooter>
          {override && (
            <Button
              variant="ghost"
              className="me-auto"
              disabled={saving || !reason.trim()}
              onClick={() => submit(true)}
            >
              {t('exposures.severity.restore', 'Use the reported severity')}
            </Button>
          )}
          <Button variant="outline" onClick={close} disabled={saving}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={() => submit(false)}
            disabled={saving || !reason.trim() || (!override && target === exposure.severity)}
          >
            {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('exposures.severity.save', 'Change severity')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
