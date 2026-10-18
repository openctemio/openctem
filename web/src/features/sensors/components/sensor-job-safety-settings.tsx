'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { PageHeader, ReadOnlyNotice, SettingsSaveBar } from '@/features/shared'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'
import {
  useTenantSettings,
  useUpdateSecuritySettings,
} from '@/features/organization/api/use-tenant-settings'
import type { TenantSettings } from '@/features/organization/types/settings.types'
import { LastChanged } from '@/features/organization/components/last-changed'
import {
  SettingsLoadError,
  SettingsLoading,
} from '@/features/organization/components/settings-load-state'
import { SensorOptInSwitches } from './sensor-opt-in-switches'
import { ToolHTTPPolicyFields, toolUserAgentError } from './tool-http-policy-fields'
import { SensorIdentityPolicySwitch } from './sensor-identity-policy-switch'
import { SensorKeyBindPolicySwitch } from './sensor-key-bind-policy-switch'
import { SharedSensorsOptOutSwitch } from './shared-sensors-opt-out-switch'

/** The scan-job part of the security section: what this page saves. */
export interface SensorJobForm {
  require_sensor_local_policy_for_private_targets: boolean
  allow_sensor_interactsh: boolean
  allow_sensor_custom_templates: boolean
  tool_http_user_agent: string
  forbid_tool_insecure_tls: boolean
}

export const SENSOR_JOB_FIELDS = [
  'require_sensor_local_policy_for_private_targets',
  'allow_sensor_interactsh',
  'allow_sensor_custom_templates',
  'tool_http_user_agent',
  'forbid_tool_insecure_tls',
] as const

export function sensorJobFormFrom(settings: TenantSettings | undefined): SensorJobForm {
  const s = settings?.security
  return {
    require_sensor_local_policy_for_private_targets:
      s?.require_sensor_local_policy_for_private_targets ?? false,
    allow_sensor_interactsh: s?.allow_sensor_interactsh ?? false,
    allow_sensor_custom_templates: s?.allow_sensor_custom_templates ?? false,
    tool_http_user_agent: s?.tool_http_user_agent ?? '',
    forbid_tool_insecure_tls: s?.forbid_tool_insecure_tls ?? false,
  }
}

/** Changes that let jobs do more on sensors, as i18n key suffixes (confirmed first). */
export function sensorLooseningsOf(saved: SensorJobForm, next: SensorJobForm): string[] {
  const out: string[] = []
  if (
    saved.require_sensor_local_policy_for_private_targets &&
    !next.require_sensor_local_policy_for_private_targets
  ) {
    out.push('privateTargets')
  }
  if (!saved.allow_sensor_interactsh && next.allow_sensor_interactsh) out.push('interactsh')
  if (!saved.allow_sensor_custom_templates && next.allow_sensor_custom_templates)
    out.push('customTemplates')
  if (saved.forbid_tool_insecure_tls && !next.forbid_tool_insecure_tls) out.push('insecureTls')
  return out
}

const LOOSENING_TEXT: Record<string, string> = {
  privateTargets: 'Private targets may go to sensors without a local policy.',
  interactsh: 'Scan jobs may use out-of-band callbacks to an external server.',
  customTemplates: 'Scan jobs may carry custom templates.',
  insecureTls: 'Scan tools may accept invalid TLS certificates.',
}

/**
 * Settings › Scanning › Sensor job safety: what scan jobs may do on the
 * organization's sensors. The fields are part of the security settings
 * section (owner only, recent sign-in) and are saved with one sticky Save;
 * the sensor key and shared-sensor switches below apply the moment they are
 * changed (their own routes). A sensor's local policy always decides first:
 * these settings only narrow what is sent.
 */
export function SensorJobSafetySettings() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const canEdit = useCanMutate('PATCH /api/v1/tenants/{tenant}/settings/security')
  const { settings, isLoading, isError, error, mutate } = useTenantSettings(tenantId)
  const { updateSecuritySettings, isUpdating } = useUpdateSecuritySettings(tenantId)

  const saved = useMemo(() => sensorJobFormFrom(settings), [settings])
  const [form, setForm] = useState<SensorJobForm>(saved)
  const [confirm, setConfirm] = useState<string[] | null>(null)
  const reset = useCallback(() => setForm(saved), [saved])
  useEffect(() => {
    reset()
  }, [reset])

  const ua = form.tool_http_user_agent.trim()
  const uaError = toolUserAgentError(ua, t)
  const dirty = JSON.stringify({ ...form, tool_http_user_agent: ua }) !== JSON.stringify(saved)

  const doSave = async () => {
    setConfirm(null)
    try {
      const result = await updateSecuritySettings({ ...form, tool_http_user_agent: ua })
      if (result) await mutate(result, { revalidate: false })
      toast.success(t('sensors.jobSafety.saved', 'Sensor job settings saved'))
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('sensors.jobSafety.saveFailed', 'Could not save the sensor job settings')
        )
      )
    }
  }
  const handleSave = () => {
    if (uaError) return
    const loosened = sensorLooseningsOf(saved, form)
    if (loosened.length > 0) setConfirm(loosened)
    else void doSave()
  }

  const header = (
    <PageHeader
      title={t('settings.item.sensor-safety', 'Sensor job safety')}
      description={t(
        'sensors.jobSafety.desc',
        "What scan jobs may do on your sensors. A sensor's own local policy always decides first; these settings only narrow what is sent."
      )}
    />
  )
  if (isLoading) return <SettingsLoading header={header} />
  if (isError)
    return (
      <SettingsLoadError header={header} message={error?.message} onRetry={() => void mutate()} />
    )
  const disabled = !canEdit

  return (
    <Main>
      {header}
      <div className="mt-2">
        <LastChanged resourceType="tenant" resourceId={tenantId} fields={SENSOR_JOB_FIELDS} />
      </div>
      {disabled && (
        <ReadOnlyNotice
          className="mt-4"
          reason={t('org.auth.ownerOnly', 'Only the organization owner can change these settings.')}
        />
      )}
      <div className="mt-5 space-y-5">
        <Card>
          <CardHeader>
            <CardTitle>{t('sensors.jobSafety.jobs', 'Scan jobs')}</CardTitle>
            <CardDescription>
              {t(
                'sensors.jobSafety.jobsDesc',
                'Sent with every scan job. Saved together with Save changes.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div id="private-targets" className="flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <Label htmlFor="tenant-private-targets-local-policy">
                  {t(
                    'sensors.jobSafety.privateTargets',
                    'Private targets need a sensor-local policy'
                  )}
                </Label>
                <p
                  className="text-sm text-muted-foreground"
                  id="tenant-private-targets-local-policy-desc"
                >
                  {t(
                    'sensors.jobSafety.privateTargetsHint',
                    'Jobs that scan private addresses (RFC 1918, internal domains) go only to sensors whose network owner installed a local policy. Other sensors leave them for one that has it.'
                  )}
                </p>
              </div>
              <Switch
                id="tenant-private-targets-local-policy"
                aria-describedby="tenant-private-targets-local-policy-desc"
                checked={form.require_sensor_local_policy_for_private_targets}
                onCheckedChange={(v) =>
                  setForm((f) => ({ ...f, require_sensor_local_policy_for_private_targets: v }))
                }
                disabled={disabled}
              />
            </div>
            <Separator />
            <div id="opt-ins">
              <SensorOptInSwitches
                value={{
                  allow_sensor_interactsh: form.allow_sensor_interactsh,
                  allow_sensor_custom_templates: form.allow_sensor_custom_templates,
                }}
                onChange={(next) => setForm((f) => ({ ...f, ...next }))}
                disabled={disabled}
              />
            </div>
            <Separator />
            <div id="tool-http">
              <ToolHTTPPolicyFields
                value={{
                  tool_http_user_agent: form.tool_http_user_agent,
                  forbid_tool_insecure_tls: form.forbid_tool_insecure_tls,
                }}
                onChange={(next) => setForm((f) => ({ ...f, ...next }))}
                disabled={disabled}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              {t('sensors.jobSafety.immediate', 'Sensor keys and shared sensors')}
            </CardTitle>
            <CardDescription>
              {t(
                'sensors.jobSafety.immediateDesc',
                'Each switch here applies as soon as you change it.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div id="sensor-policies" className="space-y-6">
              <SensorIdentityPolicySwitch />
              <SensorKeyBindPolicySwitch />
            </div>
            <Separator />
            <div id="shared-sensors">
              <SharedSensorsOptOutSwitch />
            </div>
          </CardContent>
        </Card>
      </div>

      <SettingsSaveBar
        dirty={dirty}
        saving={isUpdating}
        onSave={handleSave}
        onDiscard={reset}
        saveDisabled={!!uaError}
      />
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => !open && setConfirm(null)}
        destructive
        title={t('sensors.jobSafety.loosen.title', 'Let scan jobs do more?')}
        desc={
          <div className="space-y-2">
            <p>
              {t(
                'sensors.jobSafety.loosen.desc',
                'These changes widen what scan jobs may do on your sensors. They are recorded in the audit log at high severity.'
              )}
            </p>
            <ul className="list-disc space-y-1 ps-5">
              {(confirm ?? []).map((k) => (
                <li key={k}>{t(`sensors.jobSafety.loosen.${k}`, LOOSENING_TEXT[k] ?? k)}</li>
              ))}
            </ul>
          </div>
        }
        confirmText={t('org.auth.loosen.confirm', 'Save anyway')}
        isLoading={isUpdating}
        handleConfirm={() => void doSave()}
      />
    </Main>
  )
}
