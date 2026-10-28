'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ListChecks } from 'lucide-react'
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
import { useTranslation } from '@/context/i18n-provider'
import {
  AI_ERR_CONSENT_REQUIRED,
  updateAIUseCase,
  useAIUseCases,
  type AIDataClass,
  type AIMode,
  type AIUseCaseList,
  type AIUseCasePatch,
  type AIUseCasePolicy,
} from '@/features/ai-suggestions/api/ai-governance-api'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'

type T = ReturnType<typeof useTranslation>['t']

const MODES: AIMode[] = ['off', 'suggest', 'auto_apply']
/** `tenant_only` is set by the platform, never offered here. */
const CEILINGS: AIDataClass[] = ['public', 'internal', 'restricted']
const MIN_CONFIDENCE = 0.5
const MAX_CONFIDENCE = 0.99

const MODE_FALLBACK: Record<AIMode, string> = {
  off: 'Off',
  suggest: 'Suggest',
  auto_apply: 'Auto-apply',
}
const CEILING_FALLBACK: Record<AIDataClass, string> = {
  public: 'Public',
  internal: 'Internal',
  restricted: 'Restricted',
  tenant_only: 'Stays in your organization',
}
const USE_CASE_FALLBACK: Record<string, { title: string; desc: string }> = {
  triage: {
    title: 'Triage',
    desc: 'A verdict (real issue, likely false positive, needs information) and a severity assessment.',
  },
  remediation: {
    title: 'Remediation steps',
    desc: 'Steps to fix the finding, added to its record.',
  },
  summary: {
    title: 'Summary',
    desc: 'A short plain-language summary of the finding.',
  },
}

/** A change loosens what leaves the platform or what applies without a person. */
function loosens(prev: AIUseCasePolicy, patch: AIUseCasePatch): boolean {
  const rank: Record<AIDataClass, number> = {
    public: 0,
    internal: 1,
    restricted: 2,
    tenant_only: 3,
  }
  return (
    (patch.mode === 'auto_apply' && prev.mode !== 'auto_apply') ||
    (patch.data_class_ceiling !== undefined &&
      rank[patch.data_class_ceiling] > rank[prev.data_class_ceiling])
  )
}

function saveErrorMessage(t: T, err: unknown): string {
  if (err instanceof ApiClientError && err.code === AI_ERR_CONSENT_REQUIRED) {
    return t(
      'settings.ai.useCases.consentRequired',
      'Turn on AI triage for this organization first.'
    )
  }
  return getErrorMessage(err)
}

/**
 * Settings > AI, "Use cases": per use case, whether AI results stay off, wait
 * for a person (suggest) or apply on their own (auto-apply), the most
 * sensitive data class sent, and the confidence needed to auto-apply. Owners
 * and administrators only (the API is the authority). Turning auto-apply on
 * or raising the ceiling needs a recent sign-in: the shared API client opens
 * the re-authentication dialog and retries. Renders nothing until the API
 * offers use cases (404) or when the caller may not read them.
 */
export function AIUseCasesSection({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const { data, mutate } = useAIUseCases(true)

  if (!data || data.data.length === 0) return null

  const onSaved = async (next: AIUseCasePolicy) => {
    await mutate(
      (cur: AIUseCaseList | null | undefined) =>
        cur
          ? { ...cur, data: cur.data.map((u) => (u.use_case === next.use_case ? next : u)) }
          : cur,
      { revalidate: false }
    )
  }

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
            'Choose, per use case, whether AI results wait for a person or apply on their own, and how much data the AI may see.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="divide-y rounded-md border">
          {data.data.map((u) => (
            <UseCaseRow
              key={u.use_case}
              policy={u}
              canEdit={canEdit}
              threshold={data.downgrade_threshold}
              windowSize={data.downgrade_window}
              onSaved={onSaved}
            />
          ))}
        </div>
        <ApplyRules />
      </CardContent>
    </Card>
  )
}

function ApplyRules() {
  const { t } = useTranslation()
  return (
    <div className="rounded-md border bg-muted/40 p-3 text-sm">
      <p className="font-medium">
        {t('settings.ai.useCases.rulesTitle', 'Rules that always apply')}
      </p>
      <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
        <li>
          {t(
            'settings.ai.useCases.ruleAdditive',
            'Auto-apply only adds information: remediation steps, summaries and confirming verdicts.'
          )}
        </li>
        <li>
          {t(
            'settings.ai.useCases.ruleLowers',
            'Anything that lowers risk (a false positive, a lower severity) always becomes an approval request that a person decides.'
          )}
        </li>
        <li>
          {t(
            'settings.ai.useCases.ruleSeverity',
            'Severity changes always wait for a person, in either direction.'
          )}
        </li>
        <li>
          {t(
            'settings.ai.useCases.ruleReview',
            'A suggestion without real evidence, or with signs of a steered input, is never applied on its own.'
          )}
        </li>
      </ul>
    </div>
  )
}

interface RowProps {
  policy: AIUseCasePolicy
  canEdit: boolean
  threshold: number
  windowSize: number
  onSaved: (next: AIUseCasePolicy) => Promise<void>
}

function UseCaseRow({ policy: u, canEdit, threshold, windowSize, onSaved }: RowProps) {
  const { t } = useTranslation()
  const [mode, setMode] = useState<AIMode>(u.mode)
  const [ceiling, setCeiling] = useState<AIDataClass>(u.data_class_ceiling)
  const [confidence, setConfidence] = useState(u.min_confidence.toFixed(2))
  const [saving, setSaving] = useState(false)
  const [confirm, setConfirm] = useState<AIUseCasePatch | null>(null)

  // A save or a refresh replaces the policy: show what the server stored.
  useEffect(() => {
    setMode(u.mode)
    setCeiling(u.data_class_ceiling)
    setConfidence(u.min_confidence.toFixed(2))
  }, [u.mode, u.data_class_ceiling, u.min_confidence])

  const conf = Number(confidence)
  const confValid =
    confidence.trim() !== '' &&
    Number.isFinite(conf) &&
    conf >= MIN_CONFIDENCE &&
    conf <= MAX_CONFIDENCE

  const patch = useMemo<AIUseCasePatch>(() => {
    const p: AIUseCasePatch = {}
    if (mode !== u.mode) p.mode = mode
    if (ceiling !== u.data_class_ceiling) p.data_class_ceiling = ceiling
    if (confValid && Math.abs(conf - u.min_confidence) > 1e-9) p.min_confidence = conf
    return p
  }, [mode, ceiling, conf, confValid, u])
  const dirty = Object.keys(patch).length > 0

  const save = async (p: AIUseCasePatch) => {
    setSaving(true)
    try {
      const next = await updateAIUseCase(u.use_case, p)
      await onSaved(next)
      toast.success(t('settings.ai.useCases.saved', 'Use case saved'))
    } catch (err) {
      toast.error(saveErrorMessage(t, err))
    } finally {
      setSaving(false)
    }
  }

  const onSave = () => {
    if (!dirty || !confValid) return
    if (loosens(u, patch)) {
      setConfirm(patch)
      return
    }
    void save(patch)
  }

  const meta = USE_CASE_FALLBACK[u.use_case] ?? { title: u.use_case, desc: '' }
  const idBase = `ai-use-case-${u.use_case}`
  const downgraded = !!u.downgraded_at && u.mode !== 'auto_apply'

  return (
    <div className="space-y-3 p-3" data-testid={idBase}>
      <div>
        <p className="text-sm font-medium">
          {t(`settings.ai.useCases.name.${u.use_case}`, meta.title)}
        </p>
        {meta.desc && (
          <p className="text-sm text-muted-foreground">
            {t(`settings.ai.useCases.desc.${u.use_case}`, meta.desc)}
          </p>
        )}
      </div>

      {!u.consented && (
        <p className="text-sm text-muted-foreground" data-testid={`${idBase}-consent`}>
          {t(
            'settings.ai.useCases.consentOff',
            'Not in effect: AI triage is off for this organization, so this use case is off whatever its mode. Turn AI triage on above.'
          )}
        </p>
      )}

      {downgraded && (
        <Alert role="status">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>
            {t('settings.ai.useCases.downgradedTitle', 'Auto-apply was turned back to suggest')}
          </AlertTitle>
          <AlertDescription className="space-y-2">
            <p>
              {t(
                'settings.ai.useCases.downgraded',
                'On {date}, people overrode {percent}% or more of the last {window} suggestions, so suggestions wait for a person again.',
                {
                  date: formatDateSafe(u.downgraded_at),
                  percent: Math.round(threshold * 100),
                  window: windowSize,
                }
              )}
            </p>
            {canEdit && (
              <Button
                size="sm"
                variant="outline"
                disabled={saving}
                onClick={() => setConfirm({ mode: 'auto_apply' })}
              >
                {t('settings.ai.useCases.reenable', 'Turn auto-apply back on')}
              </Button>
            )}
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1.5">
          <Label htmlFor={`${idBase}-mode`}>{t('settings.ai.useCases.mode', 'Mode')}</Label>
          <Select
            value={mode}
            onValueChange={(v) => setMode(v as AIMode)}
            disabled={!canEdit || saving}
          >
            <SelectTrigger id={`${idBase}-mode`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {MODES.map((m) => (
                <SelectItem key={m} value={m}>
                  {t(`settings.ai.useCases.modeName.${m}`, MODE_FALLBACK[m])}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {u.consented && u.effective_mode !== u.mode && (
            <p className="text-xs text-muted-foreground">
              {t('settings.ai.useCases.effective', 'In effect: {mode}', {
                mode: t(
                  `settings.ai.useCases.modeName.${u.effective_mode}`,
                  MODE_FALLBACK[u.effective_mode] ?? u.effective_mode
                ),
              })}
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor={`${idBase}-ceiling`}>
            {t('settings.ai.useCases.ceiling', 'Most sensitive data sent')}
          </Label>
          <Select
            value={ceiling}
            onValueChange={(v) => setCeiling(v as AIDataClass)}
            disabled={!canEdit || saving}
          >
            <SelectTrigger id={`${idBase}-ceiling`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CEILINGS.map((c) => (
                <SelectItem key={c} value={c}>
                  {t(`settings.ai.useCases.ceilingName.${c}`, CEILING_FALLBACK[c])}
                </SelectItem>
              ))}
              {u.data_class_ceiling === 'tenant_only' && (
                <SelectItem value="tenant_only" disabled>
                  {t('settings.ai.useCases.ceilingName.tenant_only', CEILING_FALLBACK.tenant_only)}
                </SelectItem>
              )}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor={`${idBase}-confidence`}>
            {t('settings.ai.useCases.confidence', 'Minimum confidence to auto-apply')}
          </Label>
          <Input
            id={`${idBase}-confidence`}
            type="number"
            inputMode="decimal"
            min={MIN_CONFIDENCE}
            max={MAX_CONFIDENCE}
            step={0.01}
            value={confidence}
            onChange={(e) => setConfidence(e.target.value)}
            disabled={!canEdit || saving}
            aria-invalid={!confValid}
            aria-describedby={`${idBase}-confidence-hint`}
          />
          <p
            id={`${idBase}-confidence-hint`}
            className={confValid ? 'text-xs text-muted-foreground' : 'text-xs text-destructive'}
          >
            {t('settings.ai.useCases.confidenceHint', 'Between {min} and {max}.', {
              min: MIN_CONFIDENCE.toFixed(2),
              max: MAX_CONFIDENCE.toFixed(2),
            })}
          </p>
        </div>
      </div>

      {canEdit && (
        <div className="flex justify-end">
          <Button size="sm" onClick={onSave} disabled={!dirty || !confValid || saving}>
            {t('settings.ai.useCases.save', 'Save')}
          </Button>
        </div>
      )}

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={t('settings.ai.useCases.confirmTitle', 'Loosen this use case?')}
        desc={t(
          'settings.ai.useCases.confirmDesc',
          'Auto-apply lets AI results that only add information apply without a person, and a higher data class sends more to the AI provider. You may be asked to sign in again. The change is audited.'
        )}
        confirmText={t('settings.ai.useCases.confirm', 'Save')}
        handleConfirm={async () => {
          if (confirm) await save(confirm)
          setConfirm(null)
        }}
      />
    </div>
  )
}
