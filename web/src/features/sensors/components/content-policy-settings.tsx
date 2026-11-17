'use client'

import { useDocsHref } from '@/context/brand-provider'
import { useMemo, useState } from 'react'
import { Info } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Input } from '@/components/ui/input'
import { TagInput } from '@/components/ui/tag-input'
import { useTranslation } from '@/context/i18n-provider'
import {
  RelativeTime,
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsPage,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
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
  const initial = useMemo(() => policyToForm(data.policy), [data.policy])
  const [form, setForm] = useState<ContentPolicyForm>(initial)
  const [applyNow, setApplyNow] = useState(true)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState(false)
  const defaults = data.defaults ?? { content: {} }
  const readOnly = !canWrite || saving

  const setPin = (name: string, patch: Partial<ContentPolicyForm['content'][string]>) =>
    setForm((f) => ({ ...f, content: { ...f.content, [name]: { ...f.content[name], ...patch } } }))

  const changes = [
    form.refreshIntervalHours !== initial.refreshIntervalHours &&
      t('sensors.contentPolicy.checkEvery'),
    ...POLICY_CONTENT.map(
      (name) =>
        JSON.stringify(form.content[name]) !== JSON.stringify(initial.content[name]) &&
        contentLabel(name)
    ),
  ].filter((c): c is string => typeof c === 'string')
  const dirty = changes.length > 0

  const discard = () => {
    setForm(initial)
    setErrors({})
    setSaveError(false)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const { policy, errors: errs } = formToPolicy(form, t)
    setErrors(errs)
    if (Object.keys(errs).length > 0) return
    setSaving(true)
    setSaveError(false)
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
      setSaveError(true)
      toast.error(getErrorMessage(err, t('sensors.contentPolicy.saveError')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form
      id={FORM_ID}
      onSubmit={submit}
      className="contents"
      aria-label={t('sensors.contentPolicy.formLabel')}
    >
      <SettingsSection
        framed
        id="refresh-schedule"
        title={t('sensors.contentPolicy.schedule.title')}
        description={t('sensors.contentPolicy.schedule.description')}
        meta={
          data.updated_at && (
            <>
              {t('sensors.contentPolicy.lastChanged')} <RelativeTime date={data.updated_at} />
            </>
          )
        }
      >
        <SettingsBlock>
          <SettingsFieldGrid>
            <SettingsField
              id="refresh-interval"
              label={t('sensors.contentPolicy.checkEvery')}
              error={errors.refreshIntervalHours}
            >
              {(control) => (
                <Input
                  {...control}
                  inputMode="numeric"
                  value={form.refreshIntervalHours}
                  placeholder={hoursPlaceholder(defaults.refresh_interval_hours, t)}
                  disabled={readOnly}
                  onChange={(e) => setForm((f) => ({ ...f, refreshIntervalHours: e.target.value }))}
                />
              )}
            </SettingsField>
          </SettingsFieldGrid>
        </SettingsBlock>
        {canWrite && (
          <SettingsSwitchRow
            id="apply-now"
            label={t('sensors.contentPolicy.applyNow')}
            hint={t('sensors.contentPolicy.applyNowHint')}
            checked={applyNow}
            onCheckedChange={setApplyNow}
            disabled={saving}
          />
        )}
      </SettingsSection>

      <SettingsSection
        framed
        id="content"
        title={t('sensors.contentPolicy.content.title')}
        description={t('sensors.contentPolicy.content.description')}
      >
        {POLICY_CONTENT.map((name) => {
          const f = form.content[name]
          const kind = PIN_KIND[name]
          const def = defaults.content?.[name]
          return (
            <SettingsBlock key={name} className="@container">
              <div data-content={name} className="flex min-w-0 flex-col gap-3">
                <h3 className="text-body font-medium">{contentLabel(name)}</h3>
                <SettingsFieldGrid>
                  <SettingsField
                    id={`${name}-max-age`}
                    label={t('sensors.contentPolicy.maxAge')}
                    error={errors[`${name}.maxAgeHours`]}
                  >
                    {(control) => (
                      <Input
                        {...control}
                        inputMode="numeric"
                        value={f.maxAgeHours}
                        placeholder={hoursPlaceholder(def?.max_age_hours, t)}
                        disabled={readOnly}
                        onChange={(e) => setPin(name, { maxAgeHours: e.target.value })}
                      />
                    )}
                  </SettingsField>
                  {kind === 'rulesets' ? (
                    <SettingsField
                      id={`${name}-rulesets`}
                      label={t('sensors.contentPolicy.rulesets')}
                      hint={t('sensors.contentPolicy.rulesetsHelp')}
                      error={errors[`${name}.rulesets`]}
                    >
                      {(control) => (
                        <TagInput
                          id={control.id}
                          value={f.rulesets}
                          onChange={(rulesets) => setPin(name, { rulesets })}
                          placeholder={t('sensors.contentPolicy.rulesetsPlaceholder')}
                          maxTags={32}
                          disabled={readOnly}
                        />
                      )}
                    </SettingsField>
                  ) : (
                    <SettingsField
                      id={`${name}-version`}
                      label={t('sensors.contentPolicy.pinnedVersion')}
                      hint={PIN_HELP_KEY[kind] ? t(PIN_HELP_KEY[kind]) : undefined}
                      error={errors[`${name}.version`]}
                    >
                      {(control) => (
                        <Input
                          {...control}
                          className="font-mono"
                          value={f.version}
                          placeholder={kind === 'digest' ? 'sha256:…' : 'v10.4.9'}
                          disabled={readOnly}
                          onChange={(e) => setPin(name, { version: e.target.value })}
                        />
                      )}
                    </SettingsField>
                  )}
                </SettingsFieldGrid>
              </div>
            </SettingsBlock>
          )
        })}
      </SettingsSection>

      {canWrite && (
        <SettingsSaveBar
          form={FORM_ID}
          dirty={dirty}
          saving={saving}
          onDiscard={discard}
          changes={changes}
          error={
            saveError
              ? t('settings.saveBar.failed', "Couldn't save. Your changes are kept.")
              : undefined
          }
        />
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

  const title = t('sensors.contentPolicy.page.title')
  const description = t('sensors.contentPolicy.page.description')
  if (error || isLoading || !data) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={error ? 'error' : 'loading'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  return (
    <SettingsPage
      title={title}
      description={description}
      readOnly={!canWrite && t('sensors.contentPolicy.needsAdmin')}
      banners={
        <Alert className="max-w-settings">
          <Info className="size-4" aria-hidden />
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
      }
    >
      <PolicyForm
        key={formKey}
        data={data}
        canWrite={canWrite}
        onSaved={async () => {
          await mutate()
          setFormKey((k) => k + 1)
        }}
      />
    </SettingsPage>
  )
}
