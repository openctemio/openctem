'use client'

import { useDocsHref } from '@/context/brand-provider'
import { useState } from 'react'
import { Info, Lock, Save } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { TagInput } from '@/components/ui/tag-input'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { DOCS } from '@/lib/docs-links'
import { getErrorMessage } from '@/lib/api/error-handler'
import { updateContentPolicy, useContentPolicy } from '@/lib/api/sensor-content-hooks'
import type { ContentPolicy, ContentPolicyResponse } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { POLICY_CONTENT, contentLabel } from '../lib/content'
import {
  PIN_KIND,
  formToPolicy,
  hoursPlaceholder,
  policyToForm,
  type ContentPolicyForm,
} from '../lib/content-policy'

const FORM_ID = 'content-policy-form'

const PIN_HELP_KEY: Record<string, string> = {
  digest: 'sensors.contentPolicy.pinHelp.digest',
  tag: 'sensors.contentPolicy.pinHelp.tag',
}

function FieldError({ id, error }: { id: string; error?: string }) {
  if (!error) return null
  return (
    <p id={id} className="text-xs text-destructive">
      {error}
    </p>
  )
}

function PolicyForm({
  data,
  canWrite,
  onSaved,
}: {
  data: ContentPolicyResponse
  canWrite: boolean
  onSaved: (policy: ContentPolicy) => void
}) {
  const { t } = useTranslation()
  const [form, setForm] = useState<ContentPolicyForm>(() => policyToForm(data.policy))
  const [applyNow, setApplyNow] = useState(true)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const defaults = data.defaults ?? { content: {} }
  const readOnly = !canWrite || saving

  const setPin = (name: string, patch: Partial<ContentPolicyForm['content'][string]>) =>
    setForm((f) => ({ ...f, content: { ...f.content, [name]: { ...f.content[name], ...patch } } }))

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const { policy, errors: errs } = formToPolicy(form, t)
    setErrors(errs)
    if (Object.keys(errs).length > 0) return
    setSaving(true)
    try {
      const res = await updateContentPolicy({ policy, apply_now: applyNow })
      toast.success(
        applyNow
          ? t(
              res.commands_created === 1
                ? 'sensors.contentPolicy.savedSent.one'
                : 'sensors.contentPolicy.savedSent.other',
              undefined,
              { count: res.commands_created }
            )
          : t('sensors.contentPolicy.saved')
      )
      onSaved(res.policy)
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.contentPolicy.saveError')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form
      id={FORM_ID}
      onSubmit={submit}
      className="space-y-5"
      aria-label={t('sensors.contentPolicy.formLabel')}
    >
      <Card>
        <CardHeader>
          <CardTitle>{t('sensors.contentPolicy.schedule.title')}</CardTitle>
          <CardDescription>{t('sensors.contentPolicy.schedule.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid max-w-xs gap-1.5">
            <Label htmlFor="refresh-interval">{t('sensors.contentPolicy.checkEvery')}</Label>
            <Input
              id="refresh-interval"
              inputMode="numeric"
              value={form.refreshIntervalHours}
              placeholder={hoursPlaceholder(defaults.refresh_interval_hours, t)}
              disabled={readOnly}
              aria-invalid={!!errors.refreshIntervalHours}
              aria-describedby="refresh-interval-error"
              onChange={(e) => setForm((f) => ({ ...f, refreshIntervalHours: e.target.value }))}
            />
            <FieldError id="refresh-interval-error" error={errors.refreshIntervalHours} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('sensors.contentPolicy.content.title')}</CardTitle>
          <CardDescription>{t('sensors.contentPolicy.content.description')}</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          {POLICY_CONTENT.map((name) => {
            const f = form.content[name]
            const kind = PIN_KIND[name]
            const def = defaults.content?.[name]
            return (
              <div
                key={name}
                className="grid grid-cols-1 gap-4 py-4 first:pt-0 last:pb-0 md:grid-cols-[12rem_10rem_minmax(0,1fr)]"
                data-content={name}
              >
                <p className="text-sm font-medium md:pt-7">{contentLabel(name)}</p>
                <div className="grid gap-1.5">
                  <Label htmlFor={`${name}-max-age`}>{t('sensors.contentPolicy.maxAge')}</Label>
                  <Input
                    id={`${name}-max-age`}
                    inputMode="numeric"
                    value={f.maxAgeHours}
                    placeholder={hoursPlaceholder(def?.max_age_hours, t)}
                    disabled={readOnly}
                    aria-invalid={!!errors[`${name}.maxAgeHours`]}
                    aria-describedby={`${name}-max-age-error`}
                    onChange={(e) => setPin(name, { maxAgeHours: e.target.value })}
                  />
                  <FieldError id={`${name}-max-age-error`} error={errors[`${name}.maxAgeHours`]} />
                </div>
                {kind === 'rulesets' ? (
                  <div className="grid gap-1.5">
                    <Label>{t('sensors.contentPolicy.rulesets')}</Label>
                    <TagInput
                      value={f.rulesets}
                      onChange={(rulesets) => setPin(name, { rulesets })}
                      placeholder={t('sensors.contentPolicy.rulesetsPlaceholder')}
                      maxTags={32}
                      disabled={readOnly}
                    />
                    <p className="text-xs text-muted-foreground">
                      {t('sensors.contentPolicy.rulesetsHelp')}
                    </p>
                    <FieldError id={`${name}-rulesets-error`} error={errors[`${name}.rulesets`]} />
                  </div>
                ) : (
                  <div className="grid gap-1.5">
                    <Label htmlFor={`${name}-version`}>
                      {t('sensors.contentPolicy.pinnedVersion')}
                    </Label>
                    <Input
                      id={`${name}-version`}
                      className="font-mono"
                      value={f.version}
                      placeholder={kind === 'digest' ? 'sha256:…' : 'v10.4.9'}
                      disabled={readOnly}
                      aria-invalid={!!errors[`${name}.version`]}
                      aria-describedby={`${name}-version-help`}
                      onChange={(e) => setPin(name, { version: e.target.value })}
                    />
                    <p id={`${name}-version-help`} className="text-xs text-muted-foreground">
                      {PIN_HELP_KEY[kind] ? t(PIN_HELP_KEY[kind]) : ''}
                    </p>
                    <FieldError id={`${name}-version-error`} error={errors[`${name}.version`]} />
                  </div>
                )}
              </div>
            )
          })}
        </CardContent>
      </Card>

      {canWrite && (
        <div className="flex items-center gap-2">
          <Switch
            id="apply-now"
            checked={applyNow}
            onCheckedChange={setApplyNow}
            disabled={saving}
          />
          <Label htmlFor="apply-now">{t('sensors.contentPolicy.applyNow')}</Label>
          <span className="text-xs text-muted-foreground">
            {t('sensors.contentPolicy.applyNowHint')}
          </span>
        </div>
      )}
    </form>
  )
}

/**
 * Settings → Scanning → Scanner content (api RFC-031): the tenant's policy for
 * the data scanners use (refresh interval, maximum age, pinned versions,
 * semgrep rulesets). Sources and mirrors are the sensor host's configuration.
 * Read-only without sensors:write.
 */
export function ContentPolicySettings() {
  const docsHref = useDocsHref()
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const { data, error, isLoading, mutate } = useContentPolicy()
  // Re-mount the form after a save so it shows what the API stored.
  const [formKey, setFormKey] = useState(0)

  return (
    <>
      <PageHeader
        title={t('sensors.contentPolicy.page.title')}
        description={t('sensors.contentPolicy.page.description')}
      >
        {canWrite && data && (
          <Button type="submit" form={FORM_ID} size="sm">
            <Save className="h-4 w-4" />
            {t('sensors.contentPolicy.saveChanges')}
          </Button>
        )}
      </PageHeader>

      <div className="mt-5 space-y-5">
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            <p>
              {t('sensors.contentPolicy.sourceNote')}{' '}
              <a
                href={docsHref(DOCS.scanning.scannerContent)}
                target="_blank"
                rel="noreferrer"
                className="underline underline-offset-2"
              >
                {t('sensors.contentPolicy.docsLink')}
              </a>
            </p>
          </AlertDescription>
        </Alert>

        {!canWrite && (
          <p className="inline-flex items-center gap-1 text-sm text-muted-foreground">
            <Lock className="h-3.5 w-3.5" aria-hidden />
            {t('sensors.contentPolicy.needsAdmin')}
          </p>
        )}

        {error ? (
          <ErrorState
            title={t('sensors.contentPolicy.errorTitle')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : isLoading || !data ? (
          <div className="space-y-5" aria-busy>
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-72 w-full" />
          </div>
        ) : (
          <>
            <PolicyForm
              key={formKey}
              data={data}
              canWrite={canWrite}
              onSaved={async () => {
                await mutate()
                setFormKey((k) => k + 1)
              }}
            />
            {data.updated_at && (
              <p className="text-xs text-muted-foreground">
                {t('sensors.contentPolicy.lastChanged')}{' '}
                <RelativeTime date={data.updated_at} className="text-xs" />
              </p>
            )}
          </>
        )}
      </div>
    </>
  )
}
