'use client'

/**
 * System > Platform scanning: "Require a verified domain before platform
 * sensors scan a target" (RFC-054 §8.1). Off by default: the organization's
 * scope entry is the authorization. A public multi-tenant cloud turns it on,
 * so platform sensors (and intrusive probes on any sensor) reach only targets
 * under a domain the organization proved it owns. The scope gate, the deny
 * list, scan zones and tier ceilings stay either way. A change needs a super
 * admin, a reason and a fresh authenticator code; it is audited and the other
 * administrators are emailed.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'

export interface PlatformSensorProofFormProps {
  required: boolean
  canEdit: boolean
  onSave: (required: boolean, reason: string, code: string) => Promise<void>
}

export function PlatformSensorProofForm({
  required,
  canEdit,
  onSave,
}: PlatformSensorProofFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [value, setValue] = useState(required)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => setValue(required), [required])
  const dirty = value !== required

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(value, reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      setCode('')
      toast.success(t('admin.proof.saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.proof.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.proof.title')}</CardTitle>
          <CardDescription>{t('admin.proof.desc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex items-start justify-between gap-4">
            <Label htmlFor={`${id}-switch`} className="grid min-w-0 gap-1 font-normal">
              <span className="font-medium">{t('admin.proof.label')}</span>
              <span className="text-sm text-muted-foreground">
                {value ? t('admin.proof.onHint') : t('admin.proof.offHint')}
              </span>
            </Label>
            <Switch
              id={`${id}-switch`}
              checked={value}
              onCheckedChange={setValue}
              disabled={!canEdit || busy}
            />
          </div>
          <p className="text-sm text-muted-foreground">{t('admin.proof.recommend')}</p>
          <p className="text-sm text-muted-foreground">{t('admin.proof.alwaysOn')}</p>
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setOpen(true)} disabled={!dirty || busy}>
                {t('admin.scanPolicy.save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('admin.scanPolicy.superOnly')}</p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title={value ? t('admin.proof.confirmOnTitle') : t('admin.proof.confirmOffTitle')}
        desc={<p>{value ? t('admin.proof.confirmOnDesc') : t('admin.proof.confirmOffDesc')}</p>}
        disabled={code.trim().length < 6 || !reason.trim()}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.scanPolicy.saving')}
            </>
          ) : (
            t('admin.scanPolicy.confirm')
          )
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-reason`}>{t('admin.scanPolicy.reason')}</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-code`}>{t('admin.scanPolicy.code')}</Label>
            <Input
              id={`${id}-code`}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              aria-invalid={!!codeError}
            />
            {codeError && <p className="text-sm text-destructive">{codeError}</p>}
          </div>
        </div>
      </ConfirmDialog>
    </>
  )
}
