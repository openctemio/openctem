'use client'

import Link from '@/components/link'
import { ListOrdered } from 'lucide-react'
import { useHasPermission, Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'

import { useState, useEffect, useCallback, useId } from 'react'
import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { useTenant } from '@/context/tenant-provider'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Slider } from '@/components/ui/slider'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import { Save, RotateCcw, Info, ArrowUpDown, Loader2, AlertCircle } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  useRiskScoringSettings,
  useUpdateRiskScoring,
  useRiskScoringPreview,
  useRecalculateRiskScores,
  useRiskScoringPresets,
} from '@/features/organization/api/use-risk-scoring-settings'
import type {
  ScoreCompositionMode,
  RiskScoringSettings,
  RiskScoringPreviewResponse,
} from '@/features/organization/types/settings.types'
import { ScoringImpactDialog } from '@/features/organization/components/scoring-impact-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { getErrorMessage } from '@/lib/api/error-handler'

function LoadingSkeleton() {
  const { t } = useTranslation()
  const PAGE_TITLE = t('riskScore.settings.page.title', 'Risk scoring')
  const PAGE_DESCRIPTION = t(
    'riskScore.settings.page.desc',
    "Configure the weights and parameters that make up each asset's risk score."
  )
  return (
    <Main>
      <PageStack>
        <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION} />
        <div className="grid gap-5 lg:grid-cols-2">
          <Skeleton className="h-80 rounded-xl" />
          <Skeleton className="h-80 rounded-xl" />
        </div>
      </PageStack>
    </Main>
  )
}

// Visual stacked bar showing weight distribution
function WeightDistributionBar({
  weights,
}: {
  weights: { exposure: number; criticality: number; findings: number; ctem: number }
}) {
  const { t } = useTranslation()
  const segments = [
    {
      key: 'exposure',
      label: t('riskScore.settings.weight.exposure', 'Exposure'),
      color: '#ef4444',
      value: weights.exposure,
    },
    {
      key: 'criticality',
      label: t('riskScore.settings.weight.criticality', 'Criticality'),
      color: '#f97316',
      value: weights.criticality,
    },
    {
      key: 'findings',
      label: t('riskScore.settings.weight.findings', 'Findings'),
      color: '#eab308',
      value: weights.findings,
    },
    {
      key: 'ctem',
      label: t('riskScore.settings.weight.ctem', 'CTEM'),
      color: '#3b82f6',
      value: weights.ctem,
    },
  ]

  return (
    <div className="space-y-2">
      <div className="flex h-3 w-full overflow-hidden rounded-full">
        {segments.map((seg) =>
          seg.value > 0 ? (
            <div
              key={seg.key}
              className="transition-all duration-200"
              style={{ width: `${seg.value}%`, backgroundColor: seg.color }}
              title={`${seg.label}: ${seg.value}%`}
            />
          ) : null
        )}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {segments.map((seg) => (
          <div key={seg.key} className="flex items-center gap-1.5 text-xs">
            <div className="h-2 w-2 rounded-full" style={{ backgroundColor: seg.color }} />
            <span className="text-muted-foreground">
              {seg.label}: {seg.value}%
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function WeightSlider({
  label,
  value,
  onChange,
  color,
  tooltip,
}: {
  label: string
  value: number
  onChange: (v: number) => void
  color: string
  tooltip?: string
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label className="flex items-center text-sm font-medium">
          {label}
          {tooltip && <InfoTip text={tooltip} />}
        </Label>
        <span className="text-muted-foreground text-sm">{value}%</span>
      </div>
      <div className="flex items-center gap-3">
        <div className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
        <Slider
          value={[value]}
          onValueChange={([v]) => onChange(v)}
          min={0}
          max={100}
          step={5}
          className="flex-1"
        />
      </div>
    </div>
  )
}

// Copy for the known presets; an unknown preset name falls back to its capitalised name.
const PRESET_COPY: Record<string, { name: string; desc: string }> = {
  legacy: {
    name: 'riskScore.settings.preset.legacy.name',
    desc: 'riskScore.settings.preset.legacy.desc',
  },
  default: {
    name: 'riskScore.settings.preset.default.name',
    desc: 'riskScore.settings.preset.default.desc',
  },
  banking: {
    name: 'riskScore.settings.preset.banking.name',
    desc: 'riskScore.settings.preset.banking.desc',
  },
  healthcare: {
    name: 'riskScore.settings.preset.healthcare.name',
    desc: 'riskScore.settings.preset.healthcare.desc',
  },
  ecommerce: {
    name: 'riskScore.settings.preset.ecommerce.name',
    desc: 'riskScore.settings.preset.ecommerce.desc',
  },
  government: {
    name: 'riskScore.settings.preset.government.name',
    desc: 'riskScore.settings.preset.government.desc',
  },
}

function InfoTip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="text-muted-foreground hover:text-foreground ms-1 inline-flex cursor-help"
        >
          <Info className="h-3.5 w-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {text}
      </TooltipContent>
    </Tooltip>
  )
}

function NumberInput({
  label,
  value,
  onChange,
  min = 0,
  max = 100,
  step = 1,
  tooltip,
}: {
  label: string
  value: number
  onChange: (v: number) => void
  min?: number
  max?: number
  step?: number
  tooltip?: string
}) {
  const id = useId()
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="flex items-center text-xs">
        {label}
        {tooltip && <InfoTip text={tooltip} />}
      </Label>
      <Input
        id={id}
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        min={min}
        max={max}
        step={step}
        className="h-8 text-sm"
      />
    </div>
  )
}

export default function ScoringConfigurationPage() {
  const mayPriorityRules = useHasPermission(Permission.PriorityRulesRead)
  const priorityRulesOn = useModuleEnabled('priority_rules')
  const canSeePriorityRules = mayPriorityRules && priorityRulesOn
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const { settings, isLoading, error, mutate } = useRiskScoringSettings(tenantId)
  const { updateRiskScoring, isUpdating } = useUpdateRiskScoring(tenantId)
  const { previewChanges, isPreviewing } = useRiskScoringPreview(tenantId)
  const { recalculate, isRecalculating } = useRecalculateRiskScores(tenantId)
  const [confirmRecalc, setConfirmRecalc] = useState(false)
  const { presets } = useRiskScoringPresets(tenantId)

  const [config, setConfig] = useState<RiskScoringSettings | null>(null)
  const [isDirty, setIsDirty] = useState(false)
  const { t } = useTranslation()
  const PAGE_TITLE = t('riskScore.settings.page.title', 'Risk scoring')
  const PAGE_DESCRIPTION = t(
    'riskScore.settings.page.desc',
    "Configure the weights and parameters that make up each asset's risk score."
  )
  // The impact review: a whole-organization dry run shown before applying.
  const [impactOpen, setImpactOpen] = useState(false)
  const [impact, setImpact] = useState<RiskScoringPreviewResponse | null>(null)
  const [impactError, setImpactError] = useState<string | null>(null)

  // Initialize form from API data
  useEffect(() => {
    if (settings && !config) {
      setConfig(settings)
    }
  }, [settings, config])

  const updateConfig = useCallback(
    (updater: (prev: RiskScoringSettings) => RiskScoringSettings) => {
      setConfig((prev) => {
        if (!prev) return prev
        const updated = updater(prev)
        updated.preset = 'custom'
        return updated
      })
      setIsDirty(true)
      setImpact(null)
    },
    []
  )

  // Smart weight update: auto-redistribute remaining weight to other components
  const updateWeight = useCallback(
    (key: keyof RiskScoringSettings['weights'], newValue: number) => {
      updateConfig((prev) => {
        const weights = { ...prev.weights }
        const oldValue = weights[key]
        const delta = newValue - oldValue
        if (delta === 0) return prev

        weights[key] = newValue

        // Distribute -delta proportionally among the other 3 keys
        const otherKeys = (['exposure', 'criticality', 'findings', 'ctem'] as const).filter(
          (k) => k !== key
        )
        const otherSum = otherKeys.reduce((s, k) => s + weights[k], 0)

        if (otherSum > 0) {
          let remaining = -delta
          for (let i = 0; i < otherKeys.length; i++) {
            const k = otherKeys[i]
            if (i === otherKeys.length - 1) {
              // Last key gets whatever is left to avoid rounding drift
              weights[k] = Math.max(0, Math.min(100, weights[k] + remaining))
            } else {
              const share = Math.round((weights[k] / otherSum) * -delta)
              const adjusted = Math.max(0, Math.min(100, weights[k] + share))
              remaining -= adjusted - weights[k]
              weights[k] = adjusted
            }
          }
        } else {
          // All others are 0 — split equally
          const each = Math.floor((100 - newValue) / otherKeys.length)
          otherKeys.forEach((k, i) => {
            weights[k] =
              i === otherKeys.length - 1 ? 100 - newValue - each * (otherKeys.length - 1) : each
          })
        }

        return { ...prev, weights }
      })
    },
    [updateConfig]
  )

  // Save opens the impact review: the whole-organization dry run runs first
  // and the settings are applied only from the review (with step-up).
  const handleSave = async () => {
    if (!config) return
    setImpact(null)
    setImpactError(null)
    setImpactOpen(true)
    try {
      const result = await previewChanges(config)
      setImpact(result ?? null)
    } catch (err) {
      setImpactError(getErrorMessage(err))
    }
  }

  const handleApply = async () => {
    if (!config) return
    try {
      await updateRiskScoring(config)
      await mutate()
      setIsDirty(false)
      setImpactOpen(false)
      setImpact(null)
      toast.success(
        t(
          'riskScore.impact.applied',
          'Settings applied. Scores are being recomputed in the background.'
        )
      )
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  const handleReset = () => {
    if (settings) {
      setConfig(settings)
      setIsDirty(false)
      setImpact(null)
    }
  }

  const handlePresetSelect = (presetName: string) => {
    const preset = presets?.find((p) => p.name === presetName)
    if (preset) {
      setConfig(preset.config)
      setIsDirty(true)
      setImpact(null)
    }
  }

  const handleRecalculate = async () => {
    try {
      const result = await recalculate()
      if (result) {
        toast.success(
          t('riskScore.impact.recalculateQueued', '{count} assets queued for a new risk score.', {
            count: result.assets_queued,
          })
        )
        await mutate()
      }
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  // Warn on navigation with unsaved changes
  useEffect(() => {
    if (!isDirty) return
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault()
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [isDirty])

  if (error && !config) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION} />
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>
              {t('riskScore.settings.loadError', 'Failed to load scoring settings')}
            </AlertTitle>
            <AlertDescription>
              <p>
                {getErrorMessage(
                  error,
                  t('riskScore.settings.loadErrorFallback', 'The scoring settings request failed.')
                )}
              </p>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        </PageStack>
      </Main>
    )
  }

  if (isLoading || !config) {
    return <LoadingSkeleton />
  }

  // The default model (likelihood × impact) uses only the exposure and
  // criticality factors and the risk levels; weights, multipliers, finding
  // impact and CTEM points apply to the weighted compositions only.
  const weighted = config.score_composition_mode !== 'likelihood_impact'
  const weightSum =
    config.weights.exposure +
    config.weights.criticality +
    config.weights.findings +
    config.weights.ctem
  const isWeightValid = weightSum === 100

  // Risk level threshold ordering validation
  const { critical_min, high_min, medium_min, low_min } = config.risk_levels
  const isThresholdValid =
    critical_min > high_min && high_min > medium_min && medium_min > low_min && low_min > 0
  const canSave = isDirty && (!weighted || isWeightValid) && isThresholdValid && !isUpdating

  return (
    <Main>
      <PageStack>
        <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION}>
          {/* The other lever on a finding's priority: per-finding override rules. */}
          {canSeePriorityRules && (
            <Button variant="outline" size="sm" asChild>
              <Link href="/priority-rules">
                <ListOrdered className="h-4 w-4" />
                {t('riskScore.settings.priorityRules', 'Priority rules')}
              </Link>
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={handleReset} disabled={!isDirty}>
            <RotateCcw className="h-4 w-4" />
            {t('riskScore.settings.reset', 'Reset')}
          </Button>
          <Button size="sm" onClick={handleSave} disabled={!canSave}>
            {isUpdating ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {t('riskScore.impact.reviewAndSave', 'Review and save')}
          </Button>
        </PageHeader>

        {/* Preset Selector */}
        {presets && presets.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>{t('riskScore.settings.presets.title', 'Presets')}</CardTitle>
              <CardDescription>
                {t(
                  'riskScore.settings.presets.desc',
                  'Start from a preset optimized for your industry'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
                {presets.map((preset) => (
                  <button
                    key={preset.name}
                    type="button"
                    onClick={() => handlePresetSelect(preset.name)}
                    className={`rounded-lg border p-3 text-start transition-colors ${
                      config.preset === preset.name
                        ? 'border-primary bg-primary/5'
                        : 'hover:border-muted-foreground/30 border-transparent'
                    }`}
                  >
                    <div className="text-sm font-medium">
                      {PRESET_COPY[preset.name]
                        ? t(PRESET_COPY[preset.name].name, preset.name)
                        : preset.name.charAt(0).toUpperCase() + preset.name.slice(1)}
                    </div>
                    <div className="text-muted-foreground mt-0.5 text-xs">
                      {PRESET_COPY[preset.name] ? t(PRESET_COPY[preset.name].desc) : ''}
                    </div>
                  </button>
                ))}
                <div
                  className={`rounded-lg border p-3 text-start transition-colors ${
                    config.preset === 'custom'
                      ? 'border-primary bg-primary/5'
                      : 'hover:border-muted-foreground/30 border-transparent'
                  }`}
                >
                  <div className="text-sm font-medium">
                    {t('riskScore.settings.presets.custom', 'Custom')}
                  </div>
                  <div className="text-muted-foreground mt-0.5 text-xs">
                    {t('riskScore.settings.presets.customDesc', 'Manually configured values')}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {!weighted && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertTitle>{t('riskScore.model.noticeTitle', 'Likelihood × impact model')}</AlertTitle>
            <AlertDescription>
              {t(
                'riskScore.model.notice',
                'Risk is the findings score times the exposure and criticality factors below, lowered by compensating controls. Component weights, exposure multipliers, finding impact and CTEM points apply only to the weighted compositions; choose one under Score composition to edit them.'
              )}
            </AlertDescription>
          </Alert>
        )}

        <div className="grid gap-5 lg:grid-cols-2">
          {/* Component Weights: the weighted compositions only */}
          {weighted && (
            <Card>
              <CardHeader>
                <CardTitle>{t('riskScore.settings.weights.title', 'Component weights')}</CardTitle>
                <CardDescription>
                  {t(
                    'riskScore.settings.weights.desc',
                    'Adjust the weight of each factor. Weights auto-balance to 100%.'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <WeightDistributionBar weights={config.weights} />
                <WeightSlider
                  label={t('riskScore.settings.weight.exposure', 'Exposure')}
                  value={config.weights.exposure}
                  onChange={(v) => updateWeight('exposure', v)}
                  color="#ef4444" // label-ok: slider track colour, matches the weight bar segment
                  tooltip={t(
                    'riskScore.settings.weight.exposureTip',
                    "How much the asset's network exposure (public, private, isolated) affects its risk score"
                  )}
                />
                <WeightSlider
                  label={t('riskScore.settings.weight.criticality', 'Criticality')}
                  value={config.weights.criticality}
                  onChange={(v) => updateWeight('criticality', v)}
                  color="#f97316" // label-ok: slider track colour, matches the weight bar segment
                  tooltip={t(
                    'riskScore.settings.weight.criticalityTip',
                    "How much the asset's business criticality level affects its risk score"
                  )}
                />
                <WeightSlider
                  label={t('riskScore.settings.weight.findings', 'Findings')}
                  value={config.weights.findings}
                  onChange={(v) => updateWeight('findings', v)}
                  color="#eab308" // label-ok: slider track colour, matches the weight bar segment
                  tooltip={t(
                    'riskScore.settings.weight.findingsTip',
                    'How much vulnerability findings (count or severity-weighted) affect the risk score'
                  )}
                />
                <WeightSlider
                  label={t('riskScore.settings.weight.ctem', 'CTEM')}
                  value={config.weights.ctem}
                  onChange={(v) => updateWeight('ctem', v)}
                  color="#3b82f6" // label-ok: slider track colour, matches the CTEM bar segment
                  tooltip={t(
                    'riskScore.settings.weight.ctemTip',
                    'Continuous Threat Exposure Management bonus points for factors like PII exposure, internet accessibility, and compliance risk'
                  )}
                />
                {!config.ctem_points.enabled && config.weights.ctem > 0 && (
                  <p className="text-muted-foreground text-xs">
                    {t(
                      'riskScore.settings.weights.ctemOff',
                      'CTEM is disabled. Its weight will be redistributed to other components.'
                    )}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Exposure Scores */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-1">
                {t('riskScore.settings.exposure.title', 'Exposure scores')}
                <InfoTip
                  text={t(
                    'riskScore.settings.exposure.tip',
                    'Base scores assigned based on how exposed an asset is to external access. Higher scores mean more risk.'
                  )}
                />
              </CardTitle>
              <CardDescription>
                {t(
                  'riskScore.settings.exposure.desc',
                  'Base score (0-100) for each exposure level'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
                <NumberInput
                  label={t('assets.exposure.public', 'Public')}
                  tooltip={t(
                    'riskScore.settings.exposure.publicTip',
                    'Directly accessible from the internet'
                  )}
                  value={config.exposure_scores.public}
                  onChange={(v) =>
                    updateConfig((c) => ({
                      ...c,
                      exposure_scores: { ...c.exposure_scores, public: v },
                    }))
                  }
                />
                <NumberInput
                  label={t('assets.exposure.restricted', 'Restricted')}
                  tooltip={t(
                    'riskScore.settings.exposure.restrictedTip',
                    'Behind VPN or firewall, limited external access'
                  )}
                  value={config.exposure_scores.restricted}
                  onChange={(v) =>
                    updateConfig((c) => ({
                      ...c,
                      exposure_scores: { ...c.exposure_scores, restricted: v },
                    }))
                  }
                />
                <NumberInput
                  label={t('assets.exposure.private', 'Private')}
                  tooltip={t(
                    'riskScore.settings.exposure.privateTip',
                    'Internal network only, no external access'
                  )}
                  value={config.exposure_scores.private}
                  onChange={(v) =>
                    updateConfig((c) => ({
                      ...c,
                      exposure_scores: { ...c.exposure_scores, private: v },
                    }))
                  }
                />
                <NumberInput
                  label={t('assets.exposure.isolated', 'Isolated')}
                  tooltip={t(
                    'riskScore.settings.exposure.isolatedTip',
                    'Air-gapped or completely isolated from other networks'
                  )}
                  value={config.exposure_scores.isolated}
                  onChange={(v) =>
                    updateConfig((c) => ({
                      ...c,
                      exposure_scores: { ...c.exposure_scores, isolated: v },
                    }))
                  }
                />
                <NumberInput
                  label={t('assets.exposure.unknown', 'Unknown')}
                  tooltip={t(
                    'riskScore.settings.exposure.unknownTip',
                    'Exposure level has not been classified'
                  )}
                  value={config.exposure_scores.unknown}
                  onChange={(v) =>
                    updateConfig((c) => ({
                      ...c,
                      exposure_scores: { ...c.exposure_scores, unknown: v },
                    }))
                  }
                />
              </div>
              {weighted && (
                <>
                  <Separator className="my-4" />
                  <CardDescription className="mb-2 flex items-center">
                    {t('riskScore.settings.multiplier.title', 'Multipliers (0.1 - 3.0)')}
                    <InfoTip
                      text={t(
                        'riskScore.settings.multiplier.tip',
                        'Final score is multiplied by this factor based on asset exposure. A multiplier of 1.0 means no change, >1.0 amplifies risk, <1.0 reduces risk.'
                      )}
                    />
                  </CardDescription>
                  <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
                    <NumberInput
                      label={t('assets.exposure.public', 'Public')}
                      value={config.exposure_multipliers.public}
                      onChange={(v) =>
                        updateConfig((c) => ({
                          ...c,
                          exposure_multipliers: { ...c.exposure_multipliers, public: v },
                        }))
                      }
                      min={0.1}
                      max={3.0}
                      step={0.1}
                    />
                    <NumberInput
                      label={t('assets.exposure.restricted', 'Restricted')}
                      value={config.exposure_multipliers.restricted}
                      onChange={(v) =>
                        updateConfig((c) => ({
                          ...c,
                          exposure_multipliers: { ...c.exposure_multipliers, restricted: v },
                        }))
                      }
                      min={0.1}
                      max={3.0}
                      step={0.1}
                    />
                    <NumberInput
                      label={t('assets.exposure.private', 'Private')}
                      value={config.exposure_multipliers.private}
                      onChange={(v) =>
                        updateConfig((c) => ({
                          ...c,
                          exposure_multipliers: { ...c.exposure_multipliers, private: v },
                        }))
                      }
                      min={0.1}
                      max={3.0}
                      step={0.1}
                    />
                    <NumberInput
                      label={t('assets.exposure.isolated', 'Isolated')}
                      value={config.exposure_multipliers.isolated}
                      onChange={(v) =>
                        updateConfig((c) => ({
                          ...c,
                          exposure_multipliers: { ...c.exposure_multipliers, isolated: v },
                        }))
                      }
                      min={0.1}
                      max={3.0}
                      step={0.1}
                    />
                    <NumberInput
                      label={t('assets.exposure.unknown', 'Unknown')}
                      value={config.exposure_multipliers.unknown}
                      onChange={(v) =>
                        updateConfig((c) => ({
                          ...c,
                          exposure_multipliers: { ...c.exposure_multipliers, unknown: v },
                        }))
                      }
                      min={0.1}
                      max={3.0}
                      step={0.1}
                    />
                  </div>
                </>
              )}
              <Separator className="my-4" />
              <div className="space-y-1">
                <Label className="flex items-center text-sm font-medium">
                  {t('riskScore.model.label', 'Score composition')}
                  <InfoTip
                    text={t(
                      'riskScore.settings.composition.tip',
                      'Controls how the exposure multiplier combines with the weighted base score. Standard multiplies the whole score (can pin highly-exposed critical assets at 100). Amplify within headroom fills the remaining range instead, so top-risk assets keep a distinguishable ranking.'
                    )}
                  />
                </Label>
                <Select
                  value={config.score_composition_mode ?? 'multiply'}
                  onValueChange={(v) =>
                    updateConfig((c) => ({
                      ...c,
                      score_composition_mode: v as ScoreCompositionMode,
                    }))
                  }
                >
                  <SelectTrigger
                    className="h-8"
                    aria-label={t('riskScore.model.label', 'Score composition')}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="likelihood_impact">
                      {t('riskScore.model.likelihoodImpact', 'Likelihood × impact (default)')}
                    </SelectItem>
                    <SelectItem value="multiply">
                      {t('riskScore.settings.composition.multiply', 'Standard (multiply)')}
                    </SelectItem>
                    <SelectItem value="amplify_headroom">
                      {t('riskScore.settings.composition.amplify', 'Amplify within headroom')}
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-muted-foreground text-xs">
                  {!weighted
                    ? t(
                        'riskScore.model.likelihoodImpactHint',
                        'Risk = findings score × exposure % × criticality % × (1 − control reduction).'
                      )
                    : (config.score_composition_mode ?? 'multiply') === 'amplify_headroom'
                      ? t(
                          'riskScore.model.amplifyHint',
                          'Highly-exposed critical assets no longer all pin at 100. The exposure boost fills the remaining range instead of overflowing, which improves ranking at the top. An asset without an open finding scores 0.'
                        )
                      : t(
                          'riskScore.model.multiplyHint',
                          'Exposure multiplier scales the whole score. An asset without an open finding scores 0.'
                        )}
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Criticality Scores & Risk Level Thresholds */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-1">
                {t('riskScore.settings.criticality.title', 'Criticality and risk levels')}
                <InfoTip
                  text={t(
                    'riskScore.settings.criticality.tip',
                    'Criticality scores define the base risk score for each business criticality level. Risk level thresholds define the score boundaries that determine the final risk label (Critical, High, Medium, Low).'
                  )}
                />
              </CardTitle>
              <CardDescription>
                {t(
                  'riskScore.settings.criticality.desc',
                  'Asset criticality scores and risk level threshold boundaries'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label className="flex items-center text-sm font-medium">
                  {t('riskScore.settings.criticality.scores', 'Criticality scores (0–100)')}
                  <InfoTip
                    text={t(
                      'riskScore.settings.criticality.scoresTip',
                      "Base score assigned to each asset based on its criticality classification. A 'Critical' asset (e.g., payment gateway) gets a higher base score than a 'Low' asset (e.g., dev blog)."
                    )}
                  />
                </Label>
                <div className="mt-2 grid grid-cols-3 gap-2 sm:grid-cols-5">
                  <NumberInput
                    label={t('riskScore.level.critical', 'Critical')}
                    value={config.criticality_scores.critical}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        criticality_scores: { ...c.criticality_scores, critical: v },
                      }))
                    }
                  />
                  <NumberInput
                    label={t('riskScore.level.high', 'High')}
                    value={config.criticality_scores.high}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        criticality_scores: { ...c.criticality_scores, high: v },
                      }))
                    }
                  />
                  <NumberInput
                    label={t('riskScore.level.medium', 'Medium')}
                    value={config.criticality_scores.medium}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        criticality_scores: { ...c.criticality_scores, medium: v },
                      }))
                    }
                  />
                  <NumberInput
                    label={t('riskScore.level.low', 'Low')}
                    value={config.criticality_scores.low}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        criticality_scores: { ...c.criticality_scores, low: v },
                      }))
                    }
                  />
                  <NumberInput
                    label={t('riskScore.settings.level.none', 'None')}
                    value={config.criticality_scores.none}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        criticality_scores: { ...c.criticality_scores, none: v },
                      }))
                    }
                  />
                </div>
              </div>
              <Separator />
              <div>
                <div className="flex items-center justify-between">
                  <Label className="flex items-center text-sm font-medium">
                    {t('riskScore.settings.thresholds.title', 'Risk level thresholds (min score)')}
                    <InfoTip
                      text={t(
                        'riskScore.settings.thresholds.tip',
                        'Minimum score required for each risk level. E.g., if Critical=80, any asset with score >= 80 is labeled Critical. Must be in descending order.'
                      )}
                    />
                  </Label>
                  {!isThresholdValid && isDirty && (
                    <span className="text-xs font-medium text-destructive">
                      {t(
                        'riskScore.settings.thresholds.order',
                        'Must be ordered: Critical > High > Medium > Low > 0'
                      )}
                    </span>
                  )}
                </div>
                <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <NumberInput
                    label={t('riskScore.settings.minLabel', '{level} (min)', {
                      level: t('riskScore.level.critical', 'Critical'),
                    })}
                    value={config.risk_levels.critical_min}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        risk_levels: { ...c.risk_levels, critical_min: v },
                      }))
                    }
                    min={1}
                  />
                  <NumberInput
                    label={t('riskScore.settings.minLabel', '{level} (min)', {
                      level: t('riskScore.level.high', 'High'),
                    })}
                    value={config.risk_levels.high_min}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        risk_levels: { ...c.risk_levels, high_min: v },
                      }))
                    }
                    min={1}
                  />
                  <NumberInput
                    label={t('riskScore.settings.minLabel', '{level} (min)', {
                      level: t('riskScore.level.medium', 'Medium'),
                    })}
                    value={config.risk_levels.medium_min}
                    onChange={(v) =>
                      updateConfig((c) => ({
                        ...c,
                        risk_levels: { ...c.risk_levels, medium_min: v },
                      }))
                    }
                    min={1}
                  />
                  <NumberInput
                    label={t('riskScore.settings.minLabel', '{level} (min)', {
                      level: t('riskScore.level.low', 'Low'),
                    })}
                    value={config.risk_levels.low_min}
                    onChange={(v) =>
                      updateConfig((c) => ({ ...c, risk_levels: { ...c.risk_levels, low_min: v } }))
                    }
                    min={1}
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Finding & CTEM Impact: the weighted compositions only */}
          {weighted && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-1">
                  {t('riskScore.settings.impact.title', 'Finding and CTEM impact')}
                  <InfoTip
                    text={t(
                      'riskScore.settings.impact.tip',
                      'Configure how vulnerability findings and CTEM threat exposure factors contribute to the overall risk score.'
                    )}
                  />
                </CardTitle>
                <CardDescription>
                  {t(
                    'riskScore.settings.impact.desc',
                    'How findings and threat exposure factors affect scores'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label className="flex items-center text-sm font-medium">
                    {t('riskScore.settings.finding.title', 'Finding impact')}
                    <InfoTip
                      text={t(
                        'riskScore.settings.finding.tip',
                        'Determines how vulnerability findings on an asset affect its score. Count-based adds fixed points per finding. Severity-weighted adds different points based on finding severity.'
                      )}
                    />
                  </Label>
                  <div className="mt-2 space-y-3">
                    <div className="space-y-1">
                      <Label className="flex items-center text-xs">
                        {t('riskScore.settings.finding.mode', 'Mode')}
                        <InfoTip
                          text={t(
                            'riskScore.settings.finding.modeTip',
                            'Count-based: each finding adds fixed points regardless of severity. Severity-weighted: each finding adds points based on its severity level (Critical findings add more than Info findings).'
                          )}
                        />
                      </Label>
                      <Select
                        value={config.finding_impact.mode}
                        onValueChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            finding_impact: {
                              ...c.finding_impact,
                              mode: v as 'count' | 'severity_weighted',
                            },
                          }))
                        }
                      >
                        <SelectTrigger className="h-8">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="count">
                            {t('riskScore.settings.finding.modeCount', 'Count-based')}
                          </SelectItem>
                          <SelectItem value="severity_weighted">
                            {t('riskScore.settings.finding.modeSeverity', 'Severity-weighted')}
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      {config.finding_impact.mode === 'count' && (
                        <NumberInput
                          label={t('riskScore.settings.finding.perFinding', 'Per-finding points')}
                          tooltip={t(
                            'riskScore.settings.finding.perFindingTip',
                            'Points added to the score for each open finding on this asset'
                          )}
                          value={config.finding_impact.per_finding_points}
                          onChange={(v) =>
                            updateConfig((c) => ({
                              ...c,
                              finding_impact: { ...c.finding_impact, per_finding_points: v },
                            }))
                          }
                          min={1}
                          max={50}
                        />
                      )}
                      <NumberInput
                        label={t('riskScore.settings.finding.cap', 'Finding cap')}
                        tooltip={t(
                          'riskScore.settings.finding.capTip',
                          'Maximum number of findings counted toward the score. Prevents a single heavily-scanned asset from getting an unfairly high score.'
                        )}
                        value={config.finding_impact.finding_cap}
                        onChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            finding_impact: { ...c.finding_impact, finding_cap: v },
                          }))
                        }
                        min={1}
                        max={100}
                      />
                    </div>
                    {config.finding_impact.mode === 'severity_weighted' && (
                      <div>
                        <Label className="flex items-center text-xs">
                          {t(
                            'riskScore.settings.finding.weights',
                            'Severity weights (points per finding)'
                          )}
                          <InfoTip
                            text={t(
                              'riskScore.settings.finding.weightsTip',
                              'Points added per finding of each severity. E.g., if Critical=10 and an asset has 3 critical findings, it adds 30 points (capped by Finding Cap).'
                            )}
                          />
                        </Label>
                        <div className="mt-1 grid grid-cols-3 gap-2 sm:grid-cols-5">
                          <NumberInput
                            label={t('riskScore.level.critical', 'Critical')}
                            value={config.finding_impact.severity_weights.critical}
                            onChange={(v) =>
                              updateConfig((c) => ({
                                ...c,
                                finding_impact: {
                                  ...c.finding_impact,
                                  severity_weights: {
                                    ...c.finding_impact.severity_weights,
                                    critical: v,
                                  },
                                },
                              }))
                            }
                            max={50}
                          />
                          <NumberInput
                            label={t('riskScore.level.high', 'High')}
                            value={config.finding_impact.severity_weights.high}
                            onChange={(v) =>
                              updateConfig((c) => ({
                                ...c,
                                finding_impact: {
                                  ...c.finding_impact,
                                  severity_weights: {
                                    ...c.finding_impact.severity_weights,
                                    high: v,
                                  },
                                },
                              }))
                            }
                            max={50}
                          />
                          <NumberInput
                            label={t('riskScore.level.medium', 'Medium')}
                            value={config.finding_impact.severity_weights.medium}
                            onChange={(v) =>
                              updateConfig((c) => ({
                                ...c,
                                finding_impact: {
                                  ...c.finding_impact,
                                  severity_weights: {
                                    ...c.finding_impact.severity_weights,
                                    medium: v,
                                  },
                                },
                              }))
                            }
                            max={50}
                          />
                          <NumberInput
                            label={t('riskScore.level.low', 'Low')}
                            value={config.finding_impact.severity_weights.low}
                            onChange={(v) =>
                              updateConfig((c) => ({
                                ...c,
                                finding_impact: {
                                  ...c.finding_impact,
                                  severity_weights: {
                                    ...c.finding_impact.severity_weights,
                                    low: v,
                                  },
                                },
                              }))
                            }
                            max={50}
                          />
                          <NumberInput
                            label={t('riskScore.settings.severity.info', 'Info')}
                            value={config.finding_impact.severity_weights.info}
                            onChange={(v) =>
                              updateConfig((c) => ({
                                ...c,
                                finding_impact: {
                                  ...c.finding_impact,
                                  severity_weights: {
                                    ...c.finding_impact.severity_weights,
                                    info: v,
                                  },
                                },
                              }))
                            }
                            max={50}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
                <Separator />
                <div>
                  <div className="flex items-center justify-between">
                    <Label className="flex items-center text-sm font-medium">
                      {t('riskScore.settings.ctem.title', 'CTEM bonus points')}
                      <InfoTip
                        text={t(
                          'riskScore.settings.ctem.tip',
                          'Additional points added to the CTEM component based on specific threat exposure attributes of each asset. Points are additive (an asset with PII + internet exposure gets both bonuses).'
                        )}
                      />
                    </Label>
                    <div className="flex items-center gap-2">
                      <Switch
                        id="ctem-toggle"
                        checked={config.ctem_points.enabled}
                        onCheckedChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            ctem_points: { ...c.ctem_points, enabled: v },
                          }))
                        }
                      />
                      <Label htmlFor="ctem-toggle" className="text-xs">
                        {t('riskScore.settings.ctem.enabled', 'Enabled')}
                      </Label>
                    </div>
                  </div>
                  {config.ctem_points.enabled && (
                    <div className="mt-2 grid grid-cols-3 gap-2">
                      <NumberInput
                        label={t('riskScore.settings.ctem.internet', 'Internet accessible')}
                        tooltip={t(
                          'riskScore.settings.ctem.internetTip',
                          'Bonus points for assets directly reachable from the internet'
                        )}
                        value={config.ctem_points.internet_accessible}
                        onChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            ctem_points: { ...c.ctem_points, internet_accessible: v },
                          }))
                        }
                      />
                      <NumberInput
                        label={t('riskScore.settings.ctem.pii', 'PII exposed')}
                        tooltip={t(
                          'riskScore.settings.ctem.piiTip',
                          'Bonus points for assets that process or store Personally Identifiable Information'
                        )}
                        value={config.ctem_points.pii_exposed}
                        onChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            ctem_points: { ...c.ctem_points, pii_exposed: v },
                          }))
                        }
                      />
                      <NumberInput
                        label={t('riskScore.settings.ctem.phi', 'PHI exposed')}
                        tooltip={t(
                          'riskScore.settings.ctem.phiTip',
                          'Bonus points for assets that process or store Protected Health Information (HIPAA)'
                        )}
                        value={config.ctem_points.phi_exposed}
                        onChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            ctem_points: { ...c.ctem_points, phi_exposed: v },
                          }))
                        }
                      />
                      <NumberInput
                        label={t('riskScore.settings.ctem.compliance', 'High-risk compliance')}
                        tooltip={t(
                          'riskScore.settings.ctem.complianceTip',
                          'Bonus points for assets under high-risk compliance frameworks (PCI-DSS, SOX, etc.)'
                        )}
                        value={config.ctem_points.high_risk_compliance}
                        onChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            ctem_points: { ...c.ctem_points, high_risk_compliance: v },
                          }))
                        }
                      />
                      <NumberInput
                        label={t('riskScore.settings.ctem.restricted', 'Restricted data')}
                        tooltip={t(
                          'riskScore.settings.ctem.restrictedTip',
                          'Bonus points for assets that handle classified or restricted data'
                        )}
                        value={config.ctem_points.restricted_data}
                        onChange={(v) =>
                          updateConfig((c) => ({
                            ...c,
                            ctem_points: { ...c.ctem_points, restricted_data: v },
                          }))
                        }
                      />
                    </div>
                  )}
                  {!config.ctem_points.enabled && (
                    <p className="text-muted-foreground mt-1 text-xs">
                      {t(
                        'riskScore.settings.ctem.off',
                        'CTEM scoring is disabled. Enable to add bonus points for threat exposure factors.'
                      )}
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Unowned Findings Floor — CTEM "ownership unknown defaults to P2" rule */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-1">
              {t('riskScore.settings.floor.heading', 'Unowned findings floor')}
              <InfoTip
                text={t(
                  'riskScore.settings.floor.tip',
                  'CTEM playbook rule. When enabled, findings on assets with no assigned owner are floored at P2 priority. It is a strict floor: only ever raises a P3 to P2, never lowers anything and never touches P0/P1.'
                )}
              />
            </CardTitle>
            <CardDescription>
              {t(
                'riskScore.settings.floor.desc',
                'How findings on ownerless assets are prioritized'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label htmlFor="floor-unowned-toggle" className="text-sm font-medium">
                  {t('riskScore.floor.title', 'Floor unowned findings at P2')}
                </Label>
                <p className="text-muted-foreground max-w-prose text-xs">
                  {t(
                    'riskScore.floor.desc',
                    "Findings on assets with no assigned owner can't be safely deprioritized, so keep them at P2 minimum. Off by default."
                  )}
                </p>
              </div>
              <Switch
                id="floor-unowned-toggle"
                checked={config.floor_unowned_at_p2 ?? false}
                onCheckedChange={(v) => updateConfig((c) => ({ ...c, floor_unowned_at_p2: v }))}
              />
            </div>
          </CardContent>
        </Card>

        {/* Recalculate and How Scoring Works, side by side */}
        <div className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>{t('riskScore.recalc.title', 'Recalculate scores')}</CardTitle>
              <CardDescription>
                {t(
                  'riskScore.recalc.desc',
                  'Apply current scoring configuration to all assets. This may take a moment for large portfolios.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                variant="outline"
                size="sm"
                disabled={isRecalculating || isDirty}
                onClick={() => setConfirmRecalc(true)}
              >
                {isRecalculating ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ArrowUpDown className="h-4 w-4" />
                )}
                {t('riskScore.recalc.button', 'Recalculate all scores')}
              </Button>
              <ConfirmDialog
                open={confirmRecalc}
                onOpenChange={setConfirmRecalc}
                title={t(
                  'confirm.riskScore.recalcTitle',
                  'Recalculate the risk score of every asset?'
                )}
                desc={t(
                  'confirm.riskScore.recalcDesc',
                  'Every asset is queued for a new score with the saved configuration. Scores, priorities and the order of findings change for the whole organization while it runs. Findings themselves are not changed.'
                )}
                confirmText={t('confirm.riskScore.recalcConfirm', 'Recalculate all scores')}
                handleConfirm={async () => {
                  setConfirmRecalc(false)
                  await handleRecalculate()
                }}
              />
              {isDirty && (
                <p className="text-muted-foreground mt-2 text-xs">
                  {t('riskScore.recalc.saveFirst', 'Save changes before recalculating.')}
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('riskScore.settings.how.title', 'How scoring works')}</CardTitle>
            </CardHeader>
            <CardContent>
              {!weighted ? (
                <div className="text-muted-foreground space-y-2 text-sm">
                  <p>
                    {t(
                      'riskScore.model.howLikelihood',
                      'Risk = findings score × exposure factor × criticality factor × (1 − control reduction). The findings score grows with each open finding by severity, with diminishing returns; exploit signals count one severity higher.'
                    )}
                  </p>
                  <p>
                    {t(
                      'riskScore.model.howLikelihoodZero',
                      'An asset with no open finding has a risk of 0. Exposure and criticality scale risk; they are not risk on their own.'
                    )}
                  </p>
                </div>
              ) : (
                <div className="text-muted-foreground space-y-2 text-sm">
                  <p>
                    <strong className="text-foreground">
                      {t('riskScore.settings.how.formulaLabel', 'Formula:')}
                    </strong>{' '}
                    {t(
                      'riskScore.settings.how.formula',
                      'Score = (Exposure x W1 + Criticality x W2 + Findings x W3 + CTEM x W4) x Multiplier'
                    )}
                  </p>
                  <p>
                    {t(
                      'riskScore.settings.how.components',
                      'Each component produces a score (0-100) weighted by its percentage. The exposure multiplier adjusts the final score. Result is clamped to 0-100.'
                    )}
                  </p>
                  <p>
                    {t(
                      'riskScore.settings.how.ctemOff',
                      'When CTEM is disabled, its weight is redistributed proportionally to the other components.'
                    )}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
        <ScoringImpactDialog
          open={impactOpen}
          onOpenChange={setImpactOpen}
          preview={impact}
          loading={isPreviewing}
          error={impactError}
          applying={isUpdating}
          onApply={handleApply}
        />
      </PageStack>
    </Main>
  )
}
