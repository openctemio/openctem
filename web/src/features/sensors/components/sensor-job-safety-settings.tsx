'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  SettingsPage,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
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
import { SensorOptInSwitches } from './sensor-opt-in-switches'
import { ToolHTTPPolicyFields } from './tool-http-policy-fields'
import { SensorIdentityPolicySwitch } from './sensor-identity-policy-switch'
import { SensorKeyBindPolicySwitch } from './sensor-key-bind-policy-switch'
import { SharedSensorsOptOutSwitch } from './shared-sensors-opt-out-switch'

/** The scan-job part of the security section: what this page saves. */
export interface SensorJobForm {
  require_sensor_local_policy_for_private_targets: boolean
  allow_sensor_interactsh: boolean
  allow_sensor_custom_templates: boolean
  forbid_tool_insecure_tls: boolean
}

export const SENSOR_JOB_FIELDS = [
  'require_sensor_local_policy_for_private_targets',
  'allow_sensor_interactsh',
  'allow_sensor_custom_templates',
  'forbid_tool_insecure_tls',
] as const

export function sensorJobFormFrom(settings: TenantSettings | undefined): SensorJobForm {
  const s = settings?.security
  return {
    require_sensor_local_policy_for_private_targets:
      s?.require_sensor_local_policy_for_private_targets ?? false,
    allow_sensor_interactsh: s?.allow_sensor_interactsh ?? false,
    allow_sensor_custom_templates: s?.allow_sensor_custom_templates ?? false,
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
  const [saveError, setSaveError] = useState(false)
  const reset = useCallback(() => {
    setForm(saved)
    setSaveError(false)
  }, [saved])
  useEffect(() => {
    reset()
  }, [reset])

  const dirty = JSON.stringify(form) !== JSON.stringify(saved)

  const doSave = async () => {
    setConfirm(null)
    setSaveError(false)
    try {
      const result = await updateSecuritySettings(form)
      if (result) await mutate(result, { revalidate: false })
      toast.success(t('sensors.jobSafety.saved', 'Sensor job settings saved'))
    } catch (err) {
      setSaveError(true)
      toast.error(
        getErrorMessage(
          err,
          t('sensors.jobSafety.saveFailed', 'Could not save the sensor job settings')
        )
      )
    }
  }
  const handleSave = () => {
    const loosened = sensorLooseningsOf(saved, form)
    if (loosened.length > 0) setConfirm(loosened)
    else void doSave()
  }

  const changes = [
    form.require_sensor_local_policy_for_private_targets !==
      saved.require_sensor_local_policy_for_private_targets &&
      t('sensors.jobSafety.privateTargets', 'Private targets need a sensor-local policy'),
    form.allow_sensor_interactsh !== saved.allow_sensor_interactsh &&
      t('sensors.optIns.interactsh.label'),
    form.allow_sensor_custom_templates !== saved.allow_sensor_custom_templates &&
      t('sensors.optIns.customTemplates.label'),
    form.forbid_tool_insecure_tls !== saved.forbid_tool_insecure_tls &&
      t('sensors.httpPolicy.tls.label'),
  ].filter((c): c is string => typeof c === 'string')

  const title = t('settings.item.sensor-safety', 'Sensor job safety')
  const description = t(
    'sensors.jobSafety.desc',
    "What scan jobs may do on your sensors. A sensor's own local policy always decides first; these settings only narrow what is sent."
  )
  if (isLoading || isError) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={isError ? 'error' : 'loading'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  const disabled = !canEdit

  return (
    <SettingsPage
      title={title}
      description={description}
      readOnly={
        disabled &&
        t('org.auth.ownerOnly', 'Only the organization owner can change these settings.')
      }
    >
      <SettingsSection
        framed
        id="scan-jobs"
        title={t('sensors.jobSafety.jobs', 'Scan jobs')}
        description={t(
          'sensors.jobSafety.jobsDesc',
          'Sent with every scan job. Saved together with Save changes.'
        )}
        meta={
          <LastChanged resourceType="tenant" resourceId={tenantId} fields={SENSOR_JOB_FIELDS} />
        }
      >
        <div id="private-targets">
          <SettingsSwitchRow
            id="tenant-private-targets-local-policy"
            label={t(
              'sensors.jobSafety.privateTargets',
              'Private targets need a sensor-local policy'
            )}
            hint={t(
              'sensors.jobSafety.privateTargetsHint',
              'Jobs that scan private addresses (RFC 1918, internal domains) go only to sensors whose network owner installed a local policy. Other sensors leave them for one that has it.'
            )}
            checked={form.require_sensor_local_policy_for_private_targets}
            onCheckedChange={(v) =>
              setForm((f) => ({ ...f, require_sensor_local_policy_for_private_targets: v }))
            }
            disabled={disabled}
          />
        </div>
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
        <div id="tool-http">
          <ToolHTTPPolicyFields
            value={{ forbid_tool_insecure_tls: form.forbid_tool_insecure_tls }}
            onChange={(next) => setForm((f) => ({ ...f, ...next }))}
            disabled={disabled}
          />
        </div>
      </SettingsSection>

      <SettingsSection
        framed
        id="sensor-keys"
        title={t('sensors.jobSafety.immediate', 'Sensor keys and shared sensors')}
        description={t(
          'sensors.jobSafety.immediateDesc',
          'Each switch here applies as soon as you change it.'
        )}
      >
        <div id="sensor-policies">
          <SensorIdentityPolicySwitch />
          <SensorKeyBindPolicySwitch />
        </div>
        <div id="shared-sensors">
          <SharedSensorsOptOutSwitch />
        </div>
      </SettingsSection>

      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={isUpdating}
          onSave={handleSave}
          onDiscard={reset}
          changes={changes}
          error={
            saveError
              ? t('settings.saveBar.failed', "Couldn't save. Your changes are kept.")
              : undefined
          }
        />
      )}
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
    </SettingsPage>
  )
}
