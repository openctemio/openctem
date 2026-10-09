'use client'

/**
 * Create or edit a scan window policy, with a live preview of what it
 * selects and when it opens. The form checks the API's limits so most
 * mistakes show before saving; the API validates everything again and
 * checks every selector id against the organization (422 otherwise).
 */

import { useEffect, useMemo, useState } from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  createScanWindowPolicy,
  invalidateScanWindows,
  updateScanWindowPolicy,
} from '../api/use-scan-windows'
import type { SelectorOptions } from '../api/use-selector-options'
import { apiErrorCode, SCAN_WINDOW_UNKNOWN_REFERENCE } from '../lib/decision'
import {
  MAX_GRACE_MINUTES,
  emptyPolicyForm,
  formToRequest,
  policyFormErrors,
  policyToForm,
  type PolicyFormState,
} from '../lib/policy-form'
import { browserTimeZone, tierLabel, timeZoneOptions } from '../lib/schedule'
import type { ScanWindowKind, ScanWindowPolicy, ScanWindowTier } from '../types'
import { PolicyPreview } from './policy-preview'
import { OneOffsEditor, SlotsEditor } from './schedule-editor'
import { SelectorEditor } from './selector-editor'

interface PolicyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this policy; null to create one. */
  policy: ScanWindowPolicy | null
  sources: SelectorOptions
}

export function PolicyDialog({ open, onOpenChange, policy, sources }: PolicyDialogProps) {
  const { t } = useTranslation()
  const editing = !!policy
  const [form, setForm] = useState<PolicyFormState>(() => emptyPolicyForm(browserTimeZone()))
  const [touched, setTouched] = useState(false)
  const [saving, setSaving] = useState(false)
  const [serverError, setServerError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setForm(policy ? policyToForm(policy) : emptyPolicyForm(browserTimeZone()))
    setTouched(false)
    setServerError(null)
  }, [open, policy])

  const set = <K extends keyof PolicyFormState>(k: K, v: PolicyFormState[K]) =>
    setForm((f) => ({ ...f, [k]: v }))
  const errors = useMemo(() => policyFormErrors(form, t), [form, t])
  const valid = Object.keys(errors).length === 0
  const show = (k: string) => (touched ? errors[k] : undefined)
  const shown = useMemo(
    () => (touched ? errors : ({} as Record<string, string>)),
    [touched, errors]
  )
  // The preview needs a policy the API accepts; the name does not matter.
  const previewErrors = useMemo(
    () => Object.keys(errors).filter((k) => k !== 'name' && k !== 'description'),
    [errors]
  )
  const draft = useMemo(
    () =>
      previewErrors.length === 0
        ? formToRequest({ ...form, name: form.name.trim() || 'preview' })
        : null,
    [form, previewErrors]
  )
  const zones = useMemo(() => timeZoneOptions(form.timezone), [form.timezone])

  const save = async () => {
    setTouched(true)
    setServerError(null)
    if (!valid) return
    setSaving(true)
    try {
      const body = formToRequest(form)
      if (policy?.id) await updateScanWindowPolicy(policy.id, body)
      else await createScanWindowPolicy(body)
      toast.success(
        editing
          ? t('scanWindows.toast.saved', 'Policy "{name}" saved', { name: body.name ?? '' })
          : t('scanWindows.toast.created', 'Policy "{name}" created', { name: body.name ?? '' })
      )
      await invalidateScanWindows()
      onOpenChange(false)
    } catch (err) {
      setServerError(
        apiErrorCode(err) === SCAN_WINDOW_UNKNOWN_REFERENCE
          ? t(
              'scanWindows.form.err.unknownRef',
              'A selected group, unit, zone, scope entry or program no longer exists. Remove it and save again.'
            )
          : getErrorMessage(err, t('scanWindows.form.err.save', 'Could not save the policy.'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>
            {editing
              ? t('scanWindows.form.editTitle', 'Edit scan window policy')
              : t('scanWindows.form.newTitle', 'New scan window policy')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'scanWindows.form.description',
              'Allow: the selected targets are scanned only inside the windows. Blackout: never inside them. Times are in the policy time zone.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
        >
          <DialogBody>
            <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
              <div className="min-w-0 space-y-5">
                {serverError && (
                  <Alert variant="destructive" role="alert" data-testid="policy-server-error">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>{serverError}</AlertTitle>
                  </Alert>
                )}
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label htmlFor="policy-name">{t('scanWindows.form.name', 'Name')}</Label>
                    <Input
                      id="policy-name"
                      value={form.name}
                      onChange={(e) => set('name', e.target.value)}
                      placeholder={t(
                        'scanWindows.form.namePlaceholder',
                        'Production business hours'
                      )}
                      aria-invalid={!!show('name')}
                    />
                    {show('name') && <p className="text-xs text-destructive">{show('name')}</p>}
                  </div>
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label htmlFor="policy-description">
                      {t('scanWindows.form.descriptionLabel', 'Description')}
                    </Label>
                    <Textarea
                      id="policy-description"
                      rows={2}
                      value={form.description}
                      onChange={(e) => set('description', e.target.value)}
                      aria-invalid={!!show('description')}
                    />
                    {show('description') && (
                      <p className="text-xs text-destructive">{show('description')}</p>
                    )}
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="policy-kind">{t('scanWindows.form.kind', 'Kind')}</Label>
                    <Select
                      value={form.kind}
                      onValueChange={(v) => set('kind', v as ScanWindowKind)}
                    >
                      <SelectTrigger id="policy-kind">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="allow">
                          {t('scanWindows.form.kindAllow', 'Allow: scan only inside the windows')}
                        </SelectItem>
                        <SelectItem value="blackout">
                          {t(
                            'scanWindows.form.kindBlackout',
                            'Blackout: never scan inside the windows'
                          )}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="policy-tier">{t('scanWindows.form.tier', 'Applies to')}</Label>
                    <Select
                      value={String(form.minTier)}
                      onValueChange={(v) => set('minTier', Number(v) as ScanWindowTier)}
                    >
                      <SelectTrigger id="policy-tier">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {[0, 1, 2].map((tier) => (
                          <SelectItem key={tier} value={String(tier)}>
                            {tierLabel(tier, t)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label htmlFor="policy-timezone">
                      {t('scanWindows.form.timezone', 'Time zone')}
                    </Label>
                    <Select value={form.timezone} onValueChange={(v) => set('timezone', v)}>
                      <SelectTrigger
                        id="policy-timezone"
                        className="sm:w-80"
                        aria-invalid={!!show('timezone')}
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="max-h-72">
                        {zones.map((z) => (
                          <SelectItem key={z} value={z}>
                            {z}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <SlotsEditor slots={form.slots} onChange={(v) => set('slots', v)} errors={shown} />
                <OneOffsEditor
                  oneOffs={form.oneOffs}
                  timezone={form.timezone}
                  onChange={(v) => set('oneOffs', v)}
                  errors={shown}
                />
                {show('windows') && (
                  <p className="text-xs text-destructive" role="alert">
                    {show('windows')}
                  </p>
                )}

                <SelectorEditor
                  value={form.selector}
                  onChange={(v) => set('selector', v)}
                  sources={sources}
                />

                <fieldset className="grid gap-4 sm:grid-cols-3">
                  <legend className="mb-2 text-sm font-medium">
                    {t('scanWindows.form.limits', 'Limits')}
                  </legend>
                  <div className="space-y-1.5">
                    <Label htmlFor="policy-grace">
                      {t('scanWindows.form.grace', 'Grace (minutes)')}
                    </Label>
                    <Input
                      id="policy-grace"
                      inputMode="numeric"
                      value={form.graceMinutes}
                      onChange={(e) => set('graceMinutes', e.target.value)}
                      aria-invalid={!!show('graceMinutes')}
                      aria-describedby="policy-grace-hint"
                    />
                    <p id="policy-grace-hint" className="text-xs text-muted-foreground">
                      {t(
                        'scanWindows.form.graceHint',
                        'How long running work may finish after its window closes (0 to {n}).',
                        { n: MAX_GRACE_MINUTES }
                      )}
                    </p>
                    {show('graceMinutes') && (
                      <p className="text-xs text-destructive">{show('graceMinutes')}</p>
                    )}
                  </div>
                  {form.kind === 'allow' && (
                    <>
                      <div className="space-y-1.5">
                        <Label htmlFor="policy-rate">
                          {t('scanWindows.form.rate', 'Rate limit (requests/s)')}
                        </Label>
                        <Input
                          id="policy-rate"
                          inputMode="numeric"
                          value={form.rateLimitRps}
                          placeholder={t('scanWindows.form.noLimit', 'No limit')}
                          onChange={(e) => set('rateLimitRps', e.target.value)}
                          aria-invalid={!!show('rateLimitRps')}
                        />
                        {show('rateLimitRps') && (
                          <p className="text-xs text-destructive">{show('rateLimitRps')}</p>
                        )}
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="policy-concurrent">
                          {t('scanWindows.form.concurrent', 'Max concurrent jobs')}
                        </Label>
                        <Input
                          id="policy-concurrent"
                          inputMode="numeric"
                          value={form.maxConcurrent}
                          placeholder={t('scanWindows.form.noLimit', 'No limit')}
                          onChange={(e) => set('maxConcurrent', e.target.value)}
                          aria-invalid={!!show('maxConcurrent')}
                        />
                        {show('maxConcurrent') && (
                          <p className="text-xs text-destructive">{show('maxConcurrent')}</p>
                        )}
                      </div>
                    </>
                  )}
                </fieldset>

                <div className="flex items-center justify-between gap-3 rounded-md border p-3">
                  <div>
                    <Label htmlFor="policy-enabled">
                      {t('scanWindows.form.enabled', 'Enabled')}
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      {t(
                        'scanWindows.form.enabledHint',
                        'A disabled policy governs nothing and releases what it held.'
                      )}
                    </p>
                  </div>
                  <Switch
                    id="policy-enabled"
                    checked={form.enabled}
                    onCheckedChange={(v) => set('enabled', v)}
                  />
                </div>
              </div>
              <div className="lg:sticky lg:top-0 lg:self-start">
                <PolicyPreview draft={open ? draft : null} />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={saving}>
              {saving && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
              {editing ? t('common.save', 'Save') : t('scanWindows.form.create', 'Create policy')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
