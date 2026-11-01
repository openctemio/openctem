'use client'

import { useEffect, useState } from 'react'
import { Zap } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  AUTO_TRIAGE_SEVERITIES,
  MAX_AUTO_TRIAGE_DELAY_SECONDS,
  autoTriageWidens,
  updateAIAutoTriage,
  useAIAutoTriage,
  type AIAutoTriagePolicy,
  type AutoTriageSeverity,
} from '../api/use-ai-auto-triage'

const SEVERITY_FALLBACK: Record<AutoTriageSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

function same(a: AIAutoTriagePolicy, b: AIAutoTriagePolicy): boolean {
  return (
    a.enabled === b.enabled &&
    a.delay_seconds === b.delay_seconds &&
    a.severities.length === b.severities.length &&
    a.severities.every((s) => b.severities.includes(s))
  )
}

/**
 * Automatic AI triage: new findings of the chosen severities are sent to the
 * AI provider without a person asking (only while AI triage is on). Turning
 * it on or adding a severity asks for confirmation and, on the API side, a
 * recent sign-in; owners and administrators are told. Turning it off saves at
 * once.
 */
export function AIAutoTriageCard({ canEdit, aiEnabled }: { canEdit: boolean; aiEnabled: boolean }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAIAutoTriage(true)
  const [draft, setDraft] = useState<AIAutoTriagePolicy | null>(null)
  const [saving, setSaving] = useState(false)
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    if (data) setDraft({ ...data, severities: [...data.severities] })
  }, [data])

  const dirty = !!data && !!draft && !same(data, draft)
  const delayValid =
    !!draft &&
    Number.isInteger(draft.delay_seconds) &&
    draft.delay_seconds >= 0 &&
    draft.delay_seconds <= MAX_AUTO_TRIAGE_DELAY_SECONDS
  const severitiesValid = !!draft && (!draft.enabled || draft.severities.length > 0)

  const save = async () => {
    if (!draft) return
    setSaving(true)
    try {
      const next = await updateAIAutoTriage({
        enabled: draft.enabled,
        severities: draft.severities,
        delay_seconds: draft.delay_seconds,
      })
      await mutate(
        { enabled: next.enabled, severities: next.severities, delay_seconds: next.delay_seconds },
        { revalidate: false }
      )
      toast.success(t('settings.ai.autoTriage.saved', 'Automatic triage saved'))
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const onSave = () => {
    if (!data || !draft || !dirty || saving || !delayValid || !severitiesValid) return
    if (autoTriageWidens(data, draft)) {
      setConfirm(true)
      return
    }
    void save()
  }

  const disabled = !canEdit || saving

  return (
    <Card id="ai-auto-triage">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="h-4 w-4" aria-hidden />
          {t('settings.ai.autoTriage.title', 'Automatic triage')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.autoTriage.description',
            'Send new findings of the chosen severities to the AI provider without anyone asking. Works only while AI triage is on.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading || (!draft && !error) ? (
          <Skeleton className="h-6 w-1/2" />
        ) : error || !draft ? (
          <p className="text-sm text-destructive">{getErrorMessage(error)}</p>
        ) : (
          <>
            <div className="flex items-start gap-3">
              <Switch
                id="ai-auto-triage-enabled"
                checked={draft.enabled}
                disabled={disabled}
                onCheckedChange={(on) => setDraft({ ...draft, enabled: on })}
              />
              <div className="space-y-1">
                <Label htmlFor="ai-auto-triage-enabled">
                  {t('settings.ai.autoTriage.toggle', 'Triage new findings automatically')}
                </Label>
                {!aiEnabled && (
                  <p className="text-sm text-muted-foreground">
                    {t(
                      'settings.ai.autoTriage.needsAI',
                      'AI triage is off, so nothing is sent until it is turned on.'
                    )}
                  </p>
                )}
              </div>
            </div>

            <fieldset className="space-y-2" disabled={disabled}>
              <legend className="text-sm font-medium">
                {t('settings.ai.autoTriage.severities', 'Severities')}
              </legend>
              <div className="flex flex-wrap gap-4">
                {AUTO_TRIAGE_SEVERITIES.map((sev) => (
                  <div key={sev} className="flex items-center gap-2">
                    <Checkbox
                      id={`ai-auto-triage-${sev}`}
                      checked={draft.severities.includes(sev)}
                      disabled={disabled}
                      onCheckedChange={(on) =>
                        setDraft({
                          ...draft,
                          severities:
                            on === true
                              ? AUTO_TRIAGE_SEVERITIES.filter(
                                  (s) => s === sev || draft.severities.includes(s)
                                )
                              : draft.severities.filter((s) => s !== sev),
                        })
                      }
                    />
                    <Label htmlFor={`ai-auto-triage-${sev}`} className="font-normal">
                      {t(`settings.ai.autoTriage.severity.${sev}`, SEVERITY_FALLBACK[sev])}
                    </Label>
                  </div>
                ))}
              </div>
              {!severitiesValid && (
                <p className="text-sm text-destructive" role="alert">
                  {t('settings.ai.autoTriage.severityRequired', 'Choose at least one severity.')}
                </p>
              )}
            </fieldset>

            <div className="max-w-xs space-y-1">
              <Label htmlFor="ai-auto-triage-delay">
                {t('settings.ai.autoTriage.delay', 'Wait before triage (seconds)')}
              </Label>
              <Input
                id="ai-auto-triage-delay"
                type="number"
                min={0}
                max={MAX_AUTO_TRIAGE_DELAY_SECONDS}
                step={1}
                value={Number.isNaN(draft.delay_seconds) ? '' : draft.delay_seconds}
                disabled={disabled}
                aria-invalid={!delayValid}
                onChange={(e) => setDraft({ ...draft, delay_seconds: e.target.valueAsNumber })}
              />
              <p
                className={
                  delayValid ? 'text-sm text-muted-foreground' : 'text-sm text-destructive'
                }
              >
                {t(
                  'settings.ai.autoTriage.delayHint',
                  '0 to {max}. Gives duplicate findings time to merge first.',
                  { max: MAX_AUTO_TRIAGE_DELAY_SECONDS }
                )}
              </p>
            </div>
          </>
        )}

        {canEdit && (
          <SettingsSaveBar
            dirty={dirty}
            saving={saving}
            onSave={onSave}
            onDiscard={() => data && setDraft({ ...data, severities: [...data.severities] })}
          />
        )}

        <ConfirmDialog
          open={confirm}
          onOpenChange={setConfirm}
          title={t('settings.ai.autoTriage.confirmTitle', 'Send more findings automatically?')}
          desc={t(
            'settings.ai.autoTriage.confirmDesc',
            'New findings of these severities will go to the AI provider without anyone asking. You may be asked to sign in again. Owners and administrators are told, and the change is audited.'
          )}
          confirmText={t('settings.ai.autoTriage.confirm', 'Save')}
          handleConfirm={async () => {
            await save()
            setConfirm(false)
          }}
        />
      </CardContent>
    </Card>
  )
}
