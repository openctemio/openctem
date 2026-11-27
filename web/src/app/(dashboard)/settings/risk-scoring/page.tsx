'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useHasPermission, Permission } from '@/lib/permissions'
import { SettingsPage, SettingsSaveBar } from '@/features/shared'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import {
  useRecalculateRiskScores,
  useRiskScoringPresets,
  useRiskScoringPreview,
  useRiskScoringSettings,
  useUpdateRiskScoring,
} from '@/features/organization/api/use-risk-scoring-settings'
import type {
  RiskScoringPreviewResponse,
  RiskScoringSettings,
} from '@/features/organization/types/settings.types'
import { ScoringImpactDialog } from '@/features/organization/components/scoring-impact-dialog'
import {
  CompositionSection,
  CriticalitySection,
  ExposureSection,
  FindingImpactSection,
  HowScoringWorksSection,
  PresetsSection,
  RecalculateSection,
  WeightsSection,
  rebalanceWeights,
  thresholdsValid,
  type WeightKey,
} from '@/features/organization/components/risk-scoring-sections'

/** The two drafts hold the same numbers and switches (the preset name aside). */
function sameValues(a: RiskScoringSettings, b: RiskScoringSettings) {
  return JSON.stringify({ ...a, preset: undefined }) === JSON.stringify({ ...b, preset: undefined })
}

export default function ScoringConfigurationPage() {
  const { t } = useTranslation()
  const mayPriorityRules = useHasPermission(Permission.PriorityRulesRead)
  const priorityRulesOn = useModuleEnabled('priority_rules')
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const { settings, isLoading, error, mutate } = useRiskScoringSettings(tenantId)
  const { updateRiskScoring, isUpdating } = useUpdateRiskScoring(tenantId)
  const { previewChanges, isPreviewing } = useRiskScoringPreview(tenantId)
  const { recalculate, isRecalculating } = useRecalculateRiskScores(tenantId)
  const { presets } = useRiskScoringPresets(tenantId)
  const [confirmRecalc, setConfirmRecalc] = useState(false)

  // The draft being edited; the saved settings stay untouched until the impact review applies it.
  const [config, setConfig] = useState<RiskScoringSettings | null>(null)
  const [impactOpen, setImpactOpen] = useState(false)
  const [impact, setImpact] = useState<RiskScoringPreviewResponse | null>(null)
  const [impactError, setImpactError] = useState<string | null>(null)

  useEffect(() => {
    if (settings && !config) setConfig(settings)
  }, [settings, config])

  const dirty =
    !!settings &&
    !!config &&
    !(sameValues(settings, config) && (config.preset ?? '') === (settings.preset ?? ''))

  /** Edits the draft. Any edit makes it Custom, unless it brings back the saved values. */
  const update = useCallback(
    (fn: (prev: RiskScoringSettings) => RiskScoringSettings) => {
      setConfig((prev) => {
        if (!prev) return prev
        const next = fn(prev)
        const backToSaved = !!settings && sameValues(next, settings)
        return { ...next, preset: backToSaved ? settings.preset : 'custom' }
      })
      setImpact(null)
    },
    [settings]
  )

  const onWeight = useCallback(
    (key: WeightKey, value: number) =>
      update((prev) => {
        const weights = rebalanceWeights(prev.weights, key, value)
        return weights === prev.weights ? prev : { ...prev, weights }
      }),
    [update]
  )

  const onPreset = (name: string) => {
    const preset = presets?.find((p) => p.name === name)
    if (!preset) return
    setConfig(preset.config)
    setImpact(null)
  }

  const discard = () => {
    if (settings) setConfig(settings)
    setImpact(null)
  }

  // Save opens the impact review: the whole-organization dry run runs first and the
  // settings are applied only from the review (with step-up).
  const review = async () => {
    if (!config) return
    setImpact(null)
    setImpactError(null)
    setImpactOpen(true)
    try {
      setImpact((await previewChanges(config)) ?? null)
    } catch (err) {
      setImpactError(getErrorMessage(err))
    }
  }

  const apply = async () => {
    if (!config) return
    try {
      await updateRiskScoring(config)
      const fresh = await mutate()
      if (fresh) setConfig(fresh)
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

  const runRecalculate = async () => {
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

  const changes = useMemo(() => {
    if (!settings || !config) return []
    const differs = (k: keyof RiskScoringSettings) =>
      JSON.stringify(settings[k]) !== JSON.stringify(config[k])
    const out: string[] = []
    if (sameValues(settings, config)) out.push(t('riskScore.change.preset', 'Preset'))
    if (differs('score_composition_mode')) out.push(t('riskScore.model.label', 'Score composition'))
    if (differs('floor_unowned_at_p2'))
      out.push(t('riskScore.floor.title', 'Floor unowned findings at P2'))
    if (differs('weights')) out.push(t('riskScore.settings.weights.title', 'Component weights'))
    if (differs('exposure_scores'))
      out.push(t('riskScore.settings.exposure.title', 'Exposure scores'))
    if (differs('exposure_multipliers'))
      out.push(t('riskScore.change.multipliers', 'Exposure multipliers'))
    if (differs('criticality_scores'))
      out.push(t('riskScore.change.criticality', 'Criticality scores'))
    if (differs('risk_levels'))
      out.push(t('riskScore.settings.thresholds.title', 'Risk level thresholds (min score)'))
    if (differs('finding_impact')) out.push(t('riskScore.settings.finding.title', 'Finding impact'))
    if (differs('ctem_points')) out.push(t('riskScore.settings.ctem.title', 'CTEM bonus points'))
    return out
  }, [settings, config, t])

  const title = t('riskScore.settings.page.title', 'Risk scoring')
  const description = t(
    'riskScore.settings.page.desc',
    "Configure the weights and parameters that make up each asset's risk score."
  )

  if (error && !config) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state="error"
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !config) {
    return <SettingsPage title={title} description={description} state="loading" />
  }

  // The default model (likelihood × impact) uses only the exposure and criticality factors and the
  // risk levels; weights, multipliers, finding impact and CTEM points apply to the weighted ones.
  const weighted = config.score_composition_mode !== 'likelihood_impact'
  const w = config.weights
  const weightsValid = w.exposure + w.criticality + w.findings + w.ctem === 100
  const valid = (!weighted || weightsValid) && thresholdsValid(config.risk_levels)

  return (
    <SettingsPage title={title} description={description}>
      {presets && presets.length > 0 && (
        <PresetsSection presets={presets} current={config.preset} onSelect={onPreset} />
      )}
      <CompositionSection config={config} weighted={weighted} update={update} />
      {weighted && <WeightsSection config={config} onWeight={onWeight} />}
      <ExposureSection config={config} weighted={weighted} update={update} />
      <CriticalitySection config={config} update={update} />
      {weighted && <FindingImpactSection config={config} update={update} />}
      <HowScoringWorksSection weighted={weighted} />
      <RecalculateSection
        dirty={dirty}
        busy={isRecalculating}
        onRecalculate={() => setConfirmRecalc(true)}
        showPriorityRules={mayPriorityRules && priorityRulesOn}
      />
      <SettingsSaveBar
        dirty={dirty}
        saving={isUpdating}
        saveDisabled={!valid}
        onSave={() => void review()}
        onDiscard={discard}
        changes={changes}
      />
      <ConfirmDialog
        open={confirmRecalc}
        onOpenChange={setConfirmRecalc}
        title={t('confirm.riskScore.recalcTitle', 'Recalculate the risk score of every asset?')}
        desc={t(
          'confirm.riskScore.recalcDesc',
          'Every asset is queued for a new score with the saved configuration. Scores, priorities and the order of findings change for the whole organization while it runs. Findings themselves are not changed.'
        )}
        confirmText={t('confirm.riskScore.recalcConfirm', 'Recalculate all scores')}
        handleConfirm={async () => {
          setConfirmRecalc(false)
          await runRecalculate()
        }}
      />
      <ScoringImpactDialog
        open={impactOpen}
        onOpenChange={setImpactOpen}
        preview={impact}
        loading={isPreviewing}
        error={impactError}
        applying={isUpdating}
        onApply={apply}
      />
    </SettingsPage>
  )
}
