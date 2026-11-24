'use client'

import { useCallback, useEffect, useId, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsBlock, SettingsRow, SettingsSaveBar, SettingsSection } from '@/features/shared'
import { useLimitKeyLabel } from '@/features/limits/components/limits-usage-table'
import { LIMIT_KEYS, parseLimit, UNLIMITED, type LimitKey } from '@/features/limits/lib/limit-keys'
import type { SelfServiceLimitsResponse } from '@/lib/api/generated'
import { AdminApiError } from '@console/lib/admin-api/client'
import { saveSelfServiceLimits } from '../api/use-limits'
import { ReasonAndCodeFields, useReasonAndCode } from './step-up-code-hint'
import { RoleRequiredNotice } from './role-required-notice'

type Values = Record<LimitKey, string>

function toValues(d: SelfServiceLimitsResponse): Values {
  const out = {} as Values
  for (const k of LIMIT_KEYS) {
    const v = d.limits?.[k]
    out[k] = v === undefined || v === UNLIMITED ? '' : String(v)
  }
  return out
}

export interface SelfServiceLimitsFormProps {
  defaults: SelfServiceLimitsResponse
  /** False for an administrator who may read but not change them. */
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Limits: the limits an organization starts with when a person
 * creates it themselves, and the per-person organization cap. Empty means
 * unlimited, the default. Existing organizations keep theirs. A change needs
 * a fresh authenticator code.
 */
export function SelfServiceLimitsForm({ defaults, canEdit, onSaved }: SelfServiceLimitsFormProps) {
  const { t } = useTranslation()
  const keyLabel = useLimitKeyLabel()
  const initial = useMemo(() => toValues(defaults), [defaults])
  const [values, setValues] = useState<Values>(initial)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const rc = useReasonAndCode(confirmOpen)
  const [busy, setBusy] = useState(false)
  const codeId = useId()

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => setValues(initial), [initial])
  useEffect(reset, [reset])

  const invalid = LIMIT_KEYS.some((k) => parseLimit(values[k]) === null)
  const dirty = LIMIT_KEYS.some((k) => values[k] !== initial[k])
  const sources = (defaults.sources ?? []).filter((s) => s !== 'none')

  const save = async () => {
    setBusy(true)
    rc.setCodeError(null)
    const limits: Record<string, number> = {}
    for (const k of LIMIT_KEYS) {
      const v = parseLimit(values[k])
      if (v !== null && v !== UNLIMITED) limits[k] = v
    }
    try {
      await saveSelfServiceLimits({
        limits,
        version: defaults.version ?? 0,
        totp_code: rc.code.trim(),
      })
      setConfirmOpen(false)
      toast.success(t('limits.console.defaults.saved', 'Default limits saved'))
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        rc.refuseCode(e.message)
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error(
          t(
            'limits.console.defaults.conflict',
            'Another administrator changed the default limits. The latest values are shown.'
          )
        )
        onSaved()
        return
      }
      toast.error(
        e instanceof Error
          ? e.message
          : t('limits.console.defaults.saveError', 'Could not save the default limits')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <SettingsSection
        framed
        id="self-service-limits"
        title={t('limits.console.defaults.title', 'Limits of self-service organizations')}
        description={t(
          'limits.console.defaults.description',
          'The limits an organization starts with when a person creates it themselves. Leave a value empty for no limit (the default). Organizations created in this console have no limits, and existing organizations keep theirs.'
        )}
        meta={
          sources.length > 0 && (
            <span className="flex flex-wrap items-center gap-2" data-testid="limit-sources">
              {t('limits.console.sources', 'Also set by:')}
              {sources.map((s) => (
                <Badge key={s} variant="secondary">
                  {s === 'control_plane'
                    ? t('limits.console.origin.control_plane', 'The service operator')
                    : s}
                </Badge>
              ))}
            </span>
          )
        }
      >
        {LIMIT_KEYS.map((k) => (
          <SettingsRow key={k} label={keyLabel(k)}>
            <Input
              value={values[k]}
              onChange={(e) => setValues((v) => ({ ...v, [k]: e.target.value }))}
              placeholder={t('limits.unlimited', 'Unlimited')}
              inputMode="numeric"
              className="w-28"
              disabled={!canEdit}
              aria-label={keyLabel(k)}
              aria-invalid={parseLimit(values[k]) === null}
            />
          </SettingsRow>
        ))}
        {(invalid || !canEdit) && (
          <SettingsBlock>
            {invalid && (
              <p role="alert" className="text-dense text-destructive">
                {t(
                  'limits.console.invalidValue',
                  'Use a whole number of 0 or more, or leave it empty for no limit.'
                )}
              </p>
            )}
            {!canEdit && <RoleRequiredNotice needed="super_admin" />}
          </SettingsBlock>
        )}
      </SettingsSection>
      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={busy}
          saveDisabled={invalid}
          onSave={() => setConfirmOpen(true)}
          onDiscard={reset}
        />
      )}

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title={t('limits.console.defaults.confirmTitle', 'Change the default limits?')}
        desc={
          <p>
            {t(
              'limits.console.defaults.confirmDesc',
              'Applies to organizations people create from now on. Nothing changes for existing organizations. The change is recorded in the admin audit log.'
            )}
          </p>
        }
        disabled={!rc.codeOk}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('limits.console.saving', 'Saving')}
            </>
          ) : (
            t('limits.console.confirm', 'Confirm')
          )
        }
      >
        <ReasonAndCodeFields id={codeId} state={rc} withReason={false} />
      </ConfirmDialog>
    </>
  )
}
