'use client'

import { useEffect, useState } from 'react'
import { PauseCircle, PlayCircle } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  AI_AUTONOMY_MAX_LIMIT,
  loosensAutonomy,
  updateAIAutonomy,
  useAIAutonomy,
  validLimit,
  type AIAutonomy,
  type AIAutonomyInput,
} from '../api/use-ai-autonomy'

type LimitKey = 'per_hour' | 'per_day'

const toInput = (a: AIAutonomy): AIAutonomyInput => ({
  paused: a.paused,
  per_hour: a.per_hour,
  per_day: a.per_day,
})

/**
 * Settings > AI > Use cases: the one switch and the two limits on changes
 * AI agents make without a person (api docs: architecture/ai-autonomy.md). Only
 * confirming a finding can ever happen without a person; lowering risk is
 * always a request. Pausing is one click and applies at once, also to runs in
 * flight; resuming or allowing more asks for confirmation and may ask the
 * person to sign in again.
 */
export function AIAutonomyCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAIAutonomy(true)
  const [draft, setDraft] = useState<AIAutonomyInput | null>(null)
  const [saving, setSaving] = useState(false)
  const [confirm, setConfirm] = useState<AIAutonomyInput | null>(null)

  useEffect(() => {
    if (data) setDraft(toInput(data))
  }, [data])

  const save = async (next: AIAutonomyInput) => {
    setSaving(true)
    try {
      const saved = await updateAIAutonomy(next)
      await mutate(saved, { revalidate: false })
      setDraft(toInput(saved))
      toast.success(
        next.paused
          ? t('settings.ai.autonomy.pausedToast', 'Changes without a person are paused')
          : t('settings.ai.autonomy.saved', 'Saved')
      )
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  // A loosening asks first; a tightening applies at once.
  const submit = (next: AIAutonomyInput) => {
    if (data && loosensAutonomy(toInput(data), next)) setConfirm(next)
    else void save(next)
  }

  if (isLoading || (!data && !error)) {
    return (
      <Card id="ai-autonomy">
        <CardContent className="py-6">
          <Skeleton className="h-24 w-full" />
        </CardContent>
      </Card>
    )
  }
  if (error || !data || !draft) {
    return (
      <Card id="ai-autonomy">
        <CardContent className="py-6">
          <p className="text-sm text-destructive">{getErrorMessage(error)}</p>
        </CardContent>
      </Card>
    )
  }

  const dirty = draft.per_hour !== data.per_hour || draft.per_day !== data.per_day
  const valid = validLimit(draft.per_hour) && validLimit(draft.per_day)
  const disabled = !canEdit || saving

  const limitField = (key: LimitKey, label: string) => {
    const value = draft[key]
    const id = `ai-autonomy-${key}`
    return (
      <div className="space-y-2">
        <Label htmlFor={id}>{label}</Label>
        <div className="flex flex-wrap items-center gap-3">
          <Input
            id={id}
            type="number"
            inputMode="numeric"
            min={0}
            max={AI_AUTONOMY_MAX_LIMIT}
            step={1}
            className="w-32"
            disabled={disabled || value === null}
            value={value === null ? '' : String(value)}
            aria-invalid={!validLimit(value)}
            onChange={(e) => {
              const n = e.target.value === '' ? NaN : Number(e.target.value)
              setDraft({ ...draft, [key]: n })
            }}
          />
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={value === null}
              disabled={disabled}
              onCheckedChange={(on) =>
                setDraft({ ...draft, [key]: on === true ? null : (data[key] ?? 100) })
              }
            />
            {t('settings.ai.autonomy.unlimited', 'Unlimited')}
          </label>
        </div>
      </div>
    )
  }

  return (
    <Card id="ai-autonomy">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {data.paused ? (
            <PauseCircle className="h-4 w-4" aria-hidden />
          ) : (
            <PlayCircle className="h-4 w-4" aria-hidden />
          )}
          {t('settings.ai.autonomy.title', 'Changes without a person')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.autonomy.description',
            'When a use case is on auto-apply, an AI agent may confirm a finding without a person. Lowering risk (false positive, lower severity, accepting or closing) always waits for a person. Pause these changes at any time, or limit how many happen.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <p className="text-sm font-medium" role="status">
              {data.paused
                ? t('settings.ai.autonomy.stateOff', 'Paused: AI agents only suggest')
                : t('settings.ai.autonomy.stateOn', 'On: within the limits below')}
            </p>
            {data.paused && data.paused_at && (
              <p className="text-xs text-muted-foreground">
                {t('settings.ai.autonomy.pausedSince', 'Paused')}{' '}
                <RelativeTime date={data.paused_at} />
              </p>
            )}
          </div>
          {canEdit && (
            <Button
              variant={data.paused ? 'default' : 'outline'}
              disabled={saving}
              onClick={() => submit({ ...toInput(data), paused: !data.paused })}
            >
              {data.paused
                ? t('settings.ai.autonomy.resume', 'Resume')
                : t('settings.ai.autonomy.pause', 'Pause now')}
            </Button>
          )}
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {limitField('per_hour', t('settings.ai.autonomy.perHour', 'At most per hour'))}
          {limitField('per_day', t('settings.ai.autonomy.perDay', 'At most per 24 hours'))}
        </div>
        {!valid && (
          <p className="text-sm text-destructive" role="alert">
            {t(
              'settings.ai.autonomy.invalid',
              'Enter a whole number from 0 to 100,000, or choose Unlimited.'
            )}
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          {t(
            'settings.ai.autonomy.limitHint',
            'Beyond a limit, the AI agent writes its verdict as a comment for a person. 0 works like a pause.'
          )}
        </p>

        {canEdit && (
          <SettingsSaveBar
            dirty={dirty}
            saving={saving}
            saveDisabled={!valid}
            onSave={() => submit({ ...draft, paused: data.paused })}
            onDiscard={() => setDraft(toInput(data))}
          />
        )}

        <ConfirmDialog
          open={confirm !== null}
          onOpenChange={(open) => !open && setConfirm(null)}
          title={t(
            'settings.ai.autonomy.confirmTitle',
            'Let AI agents change more without a person?'
          )}
          desc={t(
            'settings.ai.autonomy.confirmDesc',
            'You may be asked to sign in again. Owners and administrators are told, and the change is recorded in the audit log.'
          )}
          confirmText={t('settings.ai.autonomy.confirm', 'Save')}
          handleConfirm={async () => {
            if (confirm) await save(confirm)
            setConfirm(null)
          }}
        />
      </CardContent>
    </Card>
  )
}
