'use client'

import { useEffect, useId, useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared/components/tone-pill'
import { saveMFAFloor } from '../api/use-platform-settings'
import type { MFAFloor, MFAFloorSettings } from '../types'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'

const RANK: Record<MFAFloor, number> = { none: 0, admins: 1, everyone: 2 }
const MAX_GRACE_DAYS = 90

export interface MFAFloorFormProps {
  settings: MFAFloorSettings
  canEdit: boolean
  onSaved: () => void
}

/** A grace field's value as days, or null while it is not a whole number from 0 to 90. */
export function graceDays(raw: string): number | null {
  if (!/^\d{1,2}$/.test(raw.trim())) return null
  const n = Number(raw)
  return n <= MAX_GRACE_DAYS ? n : null
}

/**
 * Settings > Two-factor: the lowest two-factor requirement of every
 * organization (research 308, D16). Organizations may require more, never
 * less. A person whose only reason for two-factor is the floor has a grace
 * period before sign-in asks for it. A change applies at once, needs a super
 * admin with a fresh code and a reason, and every administrator is told.
 */
export function MFAFloorForm({ settings, canEdit, onSaved }: MFAFloorFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [floor, setFloor] = useState<MFAFloor>(settings.floor)
  const [graceExisting, setGraceExisting] = useState(String(settings.grace_days_existing))
  const [graceNew, setGraceNew] = useState(String(settings.grace_days_new))
  const [confirmOpen, setConfirmOpen] = useState(false)

  useEffect(() => {
    setFloor(settings.floor)
    setGraceExisting(String(settings.grace_days_existing))
    setGraceNew(String(settings.grace_days_new))
  }, [settings])

  const existing = graceDays(graceExisting)
  const fresh = graceDays(graceNew)
  const valid = existing !== null && fresh !== null
  const dirty =
    floor !== settings.floor ||
    existing !== settings.grace_days_existing ||
    fresh !== settings.grace_days_new
  const lowering = RANK[floor] < RANK[settings.floor]

  const label: Record<MFAFloor, string> = {
    none: t('admin.mfaFloor.none', 'No floor'),
    admins: t('admin.mfaFloor.admins', 'Owners and administrators'),
    everyone: t('admin.mfaFloor.everyone', 'Everyone'),
  }
  const hint: Record<MFAFloor, string> = {
    none: t('admin.mfaFloor.noneHint', 'Each organization decides.'),
    admins: t(
      'admin.mfaFloor.adminsHint',
      'Owners, administrators and members with a privileged role.'
    ),
    everyone: t('admin.mfaFloor.everyoneHint', 'Every member of every organization.'),
  }

  const save = async (reason: string) => {
    if (existing === null || fresh === null) return
    try {
      await saveMFAFloor({
        floor,
        grace_days_existing: existing,
        grace_days_new: fresh,
        reason,
        version: settings.version,
      })
      toast.success(t('admin.mfaFloor.saved', 'Two-factor floor saved'))
      onSaved()
    } catch (e) {
      if (
        handleSaveConflict(
          e,
          onSaved,
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        return
      throw e
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle>{t('admin.mfaFloor.title', 'Two-factor floor')}</CardTitle>
            <TonePill
              tone={settings.floor === 'none' ? 'warning' : 'success'}
              label={label[settings.floor]}
            />
          </div>
          <CardDescription>
            {t(
              'admin.mfaFloor.description',
              'Who must use two-factor in every organization. Organizations can require more, never less.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {settings.recommend_raise && settings.floor === 'none' && (
            <Alert data-testid="mfa-floor-recommend">
              <AlertDescription>
                {t(
                  'admin.mfaFloor.recommend',
                  'Recommended: require two-factor for owners and administrators.'
                )}
              </AlertDescription>
            </Alert>
          )}
          <RadioGroup
            value={floor}
            onValueChange={(v) => setFloor(v as MFAFloor)}
            disabled={!canEdit}
            aria-label={t('admin.mfaFloor.title', 'Two-factor floor')}
            className="gap-2"
          >
            {(['none', 'admins', 'everyone'] as const).map((f) => (
              <div key={f} className="flex items-start gap-3 rounded-lg border p-3">
                <RadioGroupItem value={f} id={`${id}-${f}`} className="mt-0.5" />
                <div className="space-y-0.5">
                  <Label htmlFor={`${id}-${f}`} className="font-medium">
                    {label[f]}
                  </Label>
                  <p className="text-xs text-muted-foreground">{hint[f]}</p>
                </div>
              </div>
            ))}
          </RadioGroup>

          <fieldset className="space-y-2" disabled={!canEdit}>
            <legend className="text-sm font-medium">
              {t('admin.mfaFloor.grace', 'Days to set it up')}
            </legend>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor={`${id}-existing`}>
                  {t('admin.mfaFloor.graceExisting', 'Current members')}
                </Label>
                <Input
                  id={`${id}-existing`}
                  inputMode="numeric"
                  value={graceExisting}
                  onChange={(e) => setGraceExisting(e.target.value)}
                  aria-invalid={existing === null}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor={`${id}-new`}>{t('admin.mfaFloor.graceNew', 'New members')}</Label>
                <Input
                  id={`${id}-new`}
                  inputMode="numeric"
                  value={graceNew}
                  onChange={(e) => setGraceNew(e.target.value)}
                  aria-invalid={fresh === null}
                />
              </div>
            </div>
            {!valid && (
              <p className="text-sm text-destructive">
                {t('admin.mfaFloor.graceInvalid', 'Enter a whole number of days from 0 to 90.')}
              </p>
            )}
          </fieldset>

          <p className="text-xs text-muted-foreground">
            {settings.source === 'default'
              ? t('admin.mfaFloor.sourceDefault', 'Server default ({name}).', {
                  name: settings.env_var,
                })
              : t('admin.mfaFloor.sourceConsole', 'Set in this console.')}
            {settings.effective_from &&
              ' ' +
                t('admin.mfaFloor.effectiveFrom', 'In force since {date}.', {
                  date: new Date(settings.effective_from).toLocaleDateString(),
                })}
          </p>
          <SettingChangedLine change={settings} />
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setConfirmOpen(true)} disabled={!dirty || !valid}>
                {t('admin.settings.save', 'Save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')}
            </p>
          )}
        </CardContent>
      </Card>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        destructive={lowering}
        title={
          lowering
            ? t('admin.mfaFloor.confirmLowerTitle', 'Lower the two-factor floor?')
            : t('admin.mfaFloor.confirmTitle', 'Change the two-factor floor?')
        }
        desc={
          lowering
            ? t(
                'admin.mfaFloor.confirmLowerDesc',
                'Organizations that do not require two-factor themselves stop asking for it at once. Recorded in the admin audit log and sent to every administrator.'
              )
            : t(
                'admin.mfaFloor.confirmDesc',
                'Applies at once to every organization. Recorded in the admin audit log and sent to every administrator.'
              )
        }
        confirmText={t('admin.mfaFloor.confirmButton', 'Save two-factor floor')}
        onConfirm={save}
      />
    </>
  )
}
