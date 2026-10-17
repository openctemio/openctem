'use client'

/**
 * System > Platform scanning: shared sensors on this instance (RFC-100 §5).
 * The instance switch is off by default and cannot be turned on until shared
 * sensors are ready (the API refuses too). "Organizations without a
 * decision" has no default: it is unset (they are refused) until the
 * administrator chooses allow or deny, and turning the switch on needs that
 * choice in the same change. A change needs a super admin, a reason and a
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
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'

export interface SharedSensorsFormProps {
  enabled: boolean
  /** null: not chosen yet (organizations without a decision are refused). */
  newOrgs: boolean | null
  ready: boolean
  canEdit: boolean
  onSave: (enabled: boolean, newOrgs: boolean | null, reason: string, code: string) => Promise<void>
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
  // Turning shared sensors on needs an explicit choice for organizations
  // without a decision (the API refuses it otherwise).
  const needsChoice = on && orgs === null

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
            <div id={`${id}-orgs`} className="grid min-w-0 gap-1">
              <span className="font-medium">{t('admin.sharedSensors.newOrgsLabel')}</span>
              <span className="text-sm text-muted-foreground">
                {t('admin.sharedSensors.newOrgsHint')}
              </span>
            </div>
          </div>
          <RadioGroup
            aria-labelledby={`${id}-orgs`}
            value={orgs === null ? '' : orgs ? 'allow' : 'deny'}
            onValueChange={(v) => setOrgs(v === 'allow')}
            disabled={!canEdit || busy}
            className="gap-2"
          >
            <div className="flex items-center gap-2">
              <RadioGroupItem value="allow" id={`${id}-orgs-allow`} />
              <Label htmlFor={`${id}-orgs-allow`} className="font-normal">
                {t('admin.sharedSensors.newOrgsAllow')}
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupItem value="deny" id={`${id}-orgs-deny`} />
              <Label htmlFor={`${id}-orgs-deny`} className="font-normal">
                {t('admin.sharedSensors.newOrgsDeny')}
              </Label>
            </div>
          </RadioGroup>
          {orgs === null && (
            <p
              className={needsChoice ? 'text-sm text-destructive' : 'text-sm text-muted-foreground'}
              data-testid="shared-sensors-new-orgs-unset"
            >
              {t(
                needsChoice
                  ? 'admin.sharedSensors.newOrgsRequired'
                  : 'admin.sharedSensors.newOrgsUnset'
              )}
            </p>
          )}
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setOpen(true)} disabled={!dirty || busy || needsChoice}>
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
        desc={
          <>
            {orgs !== null && (
              <p>
                {t(
                  orgs
                    ? 'admin.sharedSensors.confirmNewOrgsAllow'
                    : 'admin.sharedSensors.confirmNewOrgsDeny'
                )}
              </p>
            )}
            <p>{t('admin.sharedSensors.confirmDesc')}</p>
          </>
        }
        disabled={code.trim().length < 6 || !reason.trim() || needsChoice}
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
