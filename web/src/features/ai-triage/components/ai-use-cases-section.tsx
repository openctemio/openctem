'use client'

import { useEffect, useMemo, useState } from 'react'
import { ListChecks } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  AI_DATA_CEILINGS,
  AI_USE_CASE_MODES,
  MIN_CONFIDENCE_CEILING,
  MIN_CONFIDENCE_FLOOR,
  updateAIUseCase,
  useAIUseCases,
  widensUseCase,
  validMinConfidence,
  type AIDataCeiling,
  type AIUseCase,
  type AIUseCaseInput,
  type AIUseCaseMode,
  type AIUseCaseSetting,
} from '../api/use-ai-use-cases'

const USE_CASE_FALLBACK: Record<AIUseCase, { name: string; produces: string }> = {
  triage: {
    name: 'Triage',
    produces: 'A verdict (real issue, likely false positive, needs information) and a severity.',
  },
  remediation: { name: 'Remediation steps', produces: 'Steps to fix the finding.' },
  summary: { name: 'Summary', produces: 'A short plain-language summary of the finding.' },
}

const MODE_FALLBACK: Record<AIUseCaseMode, { label: string; hint: string }> = {
  off: { label: 'Off', hint: 'Does not run.' },
  suggest: {
    label: 'Suggest',
    hint: 'Results appear as suggestions. A person applies or dismisses each one.',
  },
  auto_apply: {
    label: 'Auto-apply',
    hint: 'Results that only add information apply at once. Anything else still waits for a person.',
  },
}

const CEILING_FALLBACK: Record<AIDataCeiling, { label: string; hint: string }> = {
  public: { label: 'Public', hint: 'Public ids only: CVE, CWE, OWASP, KEV and EPSS.' },
  internal: {
    label: 'Internal',
    hint: 'Also the finding’s title, description, severity, source, file and line, and asset facts.',
  },
  restricted: { label: 'Restricted', hint: 'Also the code snippet.' },
}

type Drafts = Partial<Record<AIUseCase, AIUseCaseInput>>

function toInput(s: AIUseCaseSetting): AIUseCaseInput {
  return { mode: s.mode, ceiling: s.ceiling, min_confidence: s.min_confidence }
}

function sameInput(a: AIUseCaseInput, b: AIUseCaseInput): boolean {
  return a.mode === b.mode && a.ceiling === b.ceiling && a.min_confidence === b.min_confidence
}

/**
 * Settings > AI > Use cases (api docs: architecture/ai-use-cases.md): for each
 * kind of AI result, whether it waits for a person or applies on its own, the
 * most sensitive data sent and the confidence needed to apply on its own.
 * Changes are saved together; a change that lets results apply on their own
 * or sends more data asks for confirmation and, on the API side, a recent
 * sign-in. Turning a use case down needs no confirmation.
 */
export function AIUseCasesSection({
  canEdit,
  aiEnabled,
}: {
  canEdit: boolean
  aiEnabled: boolean
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAIUseCases(true)
  const items = useMemo(() => data?.items ?? [], [data])
  const [drafts, setDrafts] = useState<Drafts>({})
  const [saving, setSaving] = useState(false)
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    const next: Drafts = {}
    for (const it of items) next[it.use_case] = toInput(it)
    setDrafts(next)
  }, [items])

  const changed = items.filter((it) => {
    const d = drafts[it.use_case]
    return d && !sameInput(d, toInput(it))
  })
  const dirty = changed.length > 0
  const valid = changed.every((it) => validMinConfidence(drafts[it.use_case]!.min_confidence))
  const widens = changed.some((it) => widensUseCase(toInput(it), drafts[it.use_case]!))

  const setDraft = (uc: AIUseCase, patch: Partial<AIUseCaseInput>) =>
    setDrafts((prev) => ({ ...prev, [uc]: { ...prev[uc]!, ...patch } }))

  const save = async () => {
    setSaving(true)
    try {
      // One request per changed use case; each is saved and audited on its own.
      const saved: AIUseCaseSetting[] = []
      for (const it of changed) {
        saved.push(await updateAIUseCase(it.use_case, drafts[it.use_case]!))
      }
      await mutate(
        {
          items: items.map((it) => {
            const s = saved.find((x) => x.use_case === it.use_case)
            return s ? { ...s, loosened: undefined } : it
          }),
        },
        { revalidate: true }
      )
      toast.success(t('settings.ai.useCases.saved', 'Use cases saved'))
    } catch (err) {
      toast.error(getErrorMessage(err))
      await mutate()
    } finally {
      setSaving(false)
    }
  }

  const onSave = () => {
    if (!dirty || saving || !valid) return
    if (widens) {
      setConfirm(true)
      return
    }
    void save()
  }

  const disabled = !canEdit || saving

  return (
    <Card id="ai-use-cases">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ListChecks className="h-4 w-4" aria-hidden />
          {t('settings.ai.useCases.title', 'Use cases')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.useCases.description',
            'For each kind of AI result, decide whether it waits for a person or applies on its own, and how much data the AI may see.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!aiEnabled && (
          <p className="text-sm text-muted-foreground" role="status">
            {t(
              'settings.ai.useCases.aiOff',
              'AI is off for this organization, so every use case is off until it is turned on on the Provider tab.'
            )}
          </p>
        )}

        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : error ? (
          <p className="text-sm text-destructive">{getErrorMessage(error)}</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {items.map((it) => {
              const d = drafts[it.use_case]
              if (!d) return null
              const uc = USE_CASE_FALLBACK[it.use_case]
              const id = `ai-use-case-${it.use_case}`
              const confOk = validMinConfidence(d.min_confidence)
              const auto = d.mode === 'auto_apply'
              return (
                <li
                  key={it.use_case}
                  className="grid gap-4 p-4 md:grid-cols-[minmax(0,13rem)_minmax(0,1fr)]"
                  data-testid={id}
                >
                  <div className="space-y-1">
                    <p className="font-medium" id={`${id}-name`}>
                      {t(`settings.ai.useCases.useCase.${it.use_case}.name`, uc.name)}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {t(`settings.ai.useCases.useCase.${it.use_case}.produces`, uc.produces)}
                    </p>
                  </div>

                  <div className="min-w-0 space-y-4">
                    <div className="space-y-1.5">
                      <RadioGroup
                        value={d.mode}
                        disabled={disabled}
                        onValueChange={(m) => setDraft(it.use_case, { mode: m as AIUseCaseMode })}
                        className="flex flex-wrap gap-x-4 gap-y-2"
                        aria-label={t('settings.ai.useCases.modeLabel', 'Mode for {name}', {
                          name: t(`settings.ai.useCases.useCase.${it.use_case}.name`, uc.name),
                        })}
                      >
                        {AI_USE_CASE_MODES.map((m) => (
                          <div key={m} className="flex items-center gap-2">
                            <RadioGroupItem value={m} id={`${it.use_case}-mode-${m}`} />
                            <Label htmlFor={`${it.use_case}-mode-${m}`} className="font-normal">
                              {t(`settings.ai.useCases.mode.${m}`, MODE_FALLBACK[m].label)}
                            </Label>
                          </div>
                        ))}
                      </RadioGroup>
                      <p className="text-sm text-muted-foreground">
                        {t(`settings.ai.useCases.modeHint.${d.mode}`, MODE_FALLBACK[d.mode].hint)}
                      </p>
                    </div>

                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <Label htmlFor={`${id}-ceiling`}>
                          {t('settings.ai.useCases.ceiling', 'Most sensitive data sent')}
                        </Label>
                        <Select
                          value={d.ceiling}
                          disabled={disabled}
                          onValueChange={(v) =>
                            setDraft(it.use_case, { ceiling: v as AIDataCeiling })
                          }
                        >
                          <SelectTrigger id={`${id}-ceiling`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {AI_DATA_CEILINGS.map((c) => (
                              <SelectItem key={c} value={c}>
                                {t(`settings.ai.useCases.class.${c}`, CEILING_FALLBACK[c].label)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <p className="text-sm text-muted-foreground">
                          {t(
                            `settings.ai.useCases.classHint.${d.ceiling}`,
                            CEILING_FALLBACK[d.ceiling].hint
                          )}
                        </p>
                      </div>

                      <div className="space-y-1.5">
                        <Label htmlFor={`${id}-confidence`}>
                          {t(
                            'settings.ai.useCases.minConfidence',
                            'Minimum confidence to auto-apply'
                          )}
                        </Label>
                        <Input
                          id={`${id}-confidence`}
                          type="number"
                          inputMode="decimal"
                          min={MIN_CONFIDENCE_FLOOR}
                          max={MIN_CONFIDENCE_CEILING}
                          step={0.01}
                          className="tabular-nums"
                          value={Number.isNaN(d.min_confidence) ? '' : d.min_confidence}
                          disabled={disabled || !auto}
                          aria-invalid={!confOk}
                          onChange={(e) =>
                            setDraft(it.use_case, { min_confidence: e.target.valueAsNumber })
                          }
                        />
                        <p
                          className={
                            confOk ? 'text-sm text-muted-foreground' : 'text-sm text-destructive'
                          }
                        >
                          {auto
                            ? t(
                                'settings.ai.useCases.minConfidenceHint',
                                '{min} to {max}. A result below it stays a suggestion.',
                                { min: '0.50', max: '0.99' }
                              )
                            : t(
                                'settings.ai.useCases.minConfidenceOnlyAuto',
                                'Used only in Auto-apply.'
                              )}
                        </p>
                      </div>
                    </div>

                    {it.downgrade && it.mode !== 'auto_apply' && (
                      <Alert role="status">
                        <AlertTitle>
                          {t('settings.ai.useCases.downgradedTitle', 'Moved back to Suggest')}
                        </AlertTitle>
                        <AlertDescription className="space-y-2">
                          <p>
                            {t(
                              'settings.ai.useCases.downgraded',
                              'People overrode {overrides} of its last {decisions} results, so its results wait for a person again. Check why before you turn auto-apply back on.',
                              {
                                overrides: it.downgrade.overrides,
                                decisions: it.downgrade.decisions,
                              }
                            )}{' '}
                            <RelativeTime date={it.downgrade.at} />
                          </p>
                          {canEdit && d.mode !== 'auto_apply' && (
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              disabled={saving}
                              onClick={() => setDraft(it.use_case, { mode: 'auto_apply' })}
                            >
                              {t('settings.ai.useCases.reenable', 'Turn auto-apply back on')}
                            </Button>
                          )}
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        )}

        <p className="text-sm text-muted-foreground">
          {t(
            'settings.ai.useCases.fixedRules',
            'Auto-apply never changes a severity, never lowers risk on its own and never applies a result flagged for review: a false positive still becomes an approval request. Unclassified data is never sent, and a leaked secret never sends its code snippet.'
          )}
        </p>

        {canEdit && (
          <SettingsSaveBar
            dirty={dirty}
            saving={saving}
            onSave={onSave}
            onDiscard={() => {
              const next: Drafts = {}
              for (const it of items) next[it.use_case] = toInput(it)
              setDrafts(next)
            }}
          />
        )}

        <ConfirmDialog
          open={confirm}
          onOpenChange={setConfirm}
          title={t('settings.ai.useCases.confirmTitle', 'Let AI do more?')}
          desc={t(
            'settings.ai.useCases.confirmDesc',
            'Results will apply without a person, or more data will go to the AI provider. You may be asked to sign in again. Owners and administrators are told, and the change is recorded in the audit log.'
          )}
          confirmText={t('settings.ai.useCases.confirm', 'Save')}
          handleConfirm={async () => {
            await save()
            setConfirm(false)
          }}
        />
      </CardContent>
    </Card>
  )
}
