'use client'

/**
 * System > Platform scanning: shared sensors on this instance (RFC-100 §5).
 * The instance switch is off by default and cannot be turned on until shared
 * sensors are ready (the API refuses too); "for organizations without a
 * decision" is on by default. A change needs a super admin, a reason and a
 * fresh authenticator code; it is audited and the other administrators are
 * emailed.
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
import { AdminApiError } from '../api/admin-client'

export interface SharedSensorsFormProps {
  enabled: boolean
  newOrgs: boolean
  ready: boolean
  canEdit: boolean
  onSave: (enabled: boolean, newOrgs: boolean, reason: string, code: string) => Promise<void>
}

export function SharedSensorsForm({
  enabled,
  newOrgs,
  ready,
  canEdit,
  onSave,
}: SharedSensorsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [on, setOn] = useState(enabled)
  const [orgs, setOrgs] = useState(newOrgs)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => setOn(enabled), [enabled])
  useEffect(() => setOrgs(newOrgs), [newOrgs])
  const dirty = on !== enabled || orgs !== newOrgs

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(on, orgs, reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      setCode('')
      toast.success(t('admin.sharedSensors.saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.sharedSensors.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.sharedSensors.title')}</CardTitle>
          <CardDescription>{t('admin.sharedSensors.desc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {!ready && (
            <p className="text-sm text-muted-foreground" data-testid="shared-sensors-not-ready">
              {t('admin.sharedSensors.notReady')}
            </p>
          )}
          <div className="flex items-start justify-between gap-4">
            <Label htmlFor={`${id}-enabled`} className="grid min-w-0 gap-1 font-normal">
              <span className="font-medium">{t('admin.sharedSensors.enabledLabel')}</span>
              <span className="text-sm text-muted-foreground">
                {t('admin.sharedSensors.enabledHint')}
              </span>
            </Label>
            <Switch
              id={`${id}-enabled`}
              checked={on}
              onCheckedChange={setOn}
              disabled={!canEdit || busy || (!ready && !enabled)}
            />
          </div>
          <div className="flex items-start justify-between gap-4">
            <Label htmlFor={`${id}-orgs`} className="grid min-w-0 gap-1 font-normal">
              <span className="font-medium">{t('admin.sharedSensors.newOrgsLabel')}</span>
              <span className="text-sm text-muted-foreground">
                {t('admin.sharedSensors.newOrgsHint')}
              </span>
            </Label>
            <Switch
              id={`${id}-orgs`}
              checked={orgs}
              onCheckedChange={setOrgs}
              disabled={!canEdit || busy}
            />
          </div>
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
        title={t('admin.sharedSensors.confirmTitle')}
        desc={<p>{t('admin.sharedSensors.confirmDesc')}</p>}
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
