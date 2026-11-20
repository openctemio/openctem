'use client'

/**
 * The sections of the Risk scoring settings page, in the settings page frame
 * (SettingsSection framed + SettingsRow / SettingsBlock). They show and edit
 * one draft of the settings; the page owns the draft, the save bar and the
 * impact review. Controls that a model does not use are not drawn (the
 * default likelihood x impact model ignores weights, multipliers, finding
 * impact and CTEM points).
 */

import type { ReactNode } from 'react'
import { ArrowUpDown, Check, ListOrdered, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { CommittedNumberInput } from '@/components/ui/committed-number-input'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Slider } from '@/components/ui/slider'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { categoricalVar } from '@/lib/chart-palette'
import { cn } from '@/lib/utils'
import {
  SettingsBlock,
  SettingsField,
  SettingsRow,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import type { PresetInfo, RiskScoringSettings, ScoreCompositionMode } from '../types/settings.types'

export type RiskConfig = RiskScoringSettings
export type RiskUpdate = (fn: (prev: RiskConfig) => RiskConfig) => void
type Weights = RiskConfig['weights']
export type WeightKey = keyof Weights

/** One categorical colour per weight; the bar and the rows share them. */
const WEIGHT_KEYS: WeightKey[] = ['exposure', 'criticality', 'findings', 'ctem']
const WEIGHT_COLOR = WEIGHT_KEYS.map((_, i) => categoricalVar(i))

const GRID =
  'grid min-w-0 grid-cols-[repeat(auto-fill,minmax(min(100%,7.5rem),1fr))] items-start gap-x-4 gap-y-3'

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

/** Moves one weight and shares the difference among the others, so the four add up to 100. */
export function rebalanceWeights(weights: Weights, key: WeightKey, newValue: number) {
  const next = { ...weights }
  const delta = newValue - next[key]
  if (delta === 0) return weights
  next[key] = newValue
  const others = WEIGHT_KEYS.filter((k) => k !== key)
  const otherSum = others.reduce((s, k) => s + next[k], 0)
  if (otherSum > 0) {
    let remaining = -delta
    others.forEach((k, i) => {
      if (i === others.length - 1) {
        // The last one takes what is left, so rounding never drifts.
        next[k] = Math.max(0, Math.min(100, next[k] + remaining))
      } else {
        const share = Math.round((next[k] / otherSum) * -delta)
        const adjusted = Math.max(0, Math.min(100, next[k] + share))
        remaining -= adjusted - next[k]
        next[k] = adjusted
      }
    })
  } else {
    const each = Math.floor((100 - newValue) / others.length)
    others.forEach((k, i) => {
      next[k] = i === others.length - 1 ? 100 - newValue - each * (others.length - 1) : each
    })
  }
  return next
}

/** Sets one number of a group of the settings ("exposure_scores", "public"). */
function setNumber(
  group: keyof RiskConfig,
  key: string,
  value: number
): (c: RiskConfig) => RiskConfig {
  return (c) => ({ ...c, [group]: { ...(c[group] as object), [key]: value } })
}

interface NumberFieldProps {
  label: string
  value: number
  onChange: (v: number) => void
  min?: number
  max?: number
  step?: number
  hint?: ReactNode
  error?: ReactNode
  /** Point the control at an error shown elsewhere (a message for a group of fields). */
  invalid?: boolean
  describedBy?: string
  className?: string
}

/** A labelled number field that settles its value (clamped, rounded to the step) on blur. */
function NumberField({
  label,
  value,
  onChange,
  min = 0,
  max = 100,
  step = 1,
  hint,
  error,
  invalid,
  describedBy,
  className,
}: NumberFieldProps) {
  const parse = (text: string) => {
    const n = Number(text)
    if (text.trim() === '' || !Number.isFinite(n)) return value
    const stepped = step < 1 ? Math.round(n / step) * step : n
    return Number(Math.min(max, Math.max(min, stepped)).toFixed(2))
  }
  return (
    <SettingsField label={label} hint={hint} error={error} className={className}>
      {(control) => (
        <CommittedNumberInput
          {...control}
          aria-invalid={control['aria-invalid'] ?? (invalid ? true : undefined)}
          aria-describedby={
            [control['aria-describedby'], describedBy].filter(Boolean).join(' ') || undefined
          }
          inputMode={step < 1 ? 'decimal' : 'numeric'}
          value={value}
          parse={parse}
          onCommit={onChange}
          min={min}
          max={max}
          step={step}
        />
      )}
    </SettingsField>
  )
}

const PRESET_ORDER = ['default', 'banking', 'healthcare', 'ecommerce', 'government', 'legacy']

/** The known presets in a fixed order, then any other by name (the server's order is not stable). */
function sortPresets(presets: PresetInfo[]) {
  const rank = (n: string) =>
    PRESET_ORDER.includes(n) ? PRESET_ORDER.indexOf(n) : PRESET_ORDER.length
  return [...presets].sort((a, b) => rank(a.name) - rank(b.name) || a.name.localeCompare(b.name))
}

/** The saved presets: pick one to start from; editing any value switches to Custom. */
export function PresetsSection({
  presets,
  current,
  onSelect,
}: {
  presets: PresetInfo[]
  current: string | undefined
  onSelect: (name: string) => void
}) {
  const { t } = useTranslation()
  const title = t('riskScore.settings.presets.title', 'Presets')
  return (
    <SettingsSection
      framed
      id="risk-presets"
      title={title}
      description={t(
        'riskScore.settings.presets.desc',
        'Start from a preset made for your industry. Changing any value switches to Custom.'
      )}
    >
      <RadioGroup
        value={current === 'custom' ? '' : (current ?? '')}
        onValueChange={onSelect}
        aria-label={title}
        className="gap-0"
      >
        {sortPresets(presets).map((preset) => {
          const copy = PRESET_COPY[preset.name]
          const name = copy
            ? t(copy.name, preset.name)
            : preset.name.charAt(0).toUpperCase() + preset.name.slice(1)
          const id = `risk-preset-${preset.name}`
          return (
            <div
              key={preset.name}
              data-slot="settings-row"
              className="flex min-w-0 items-start gap-3 border-t border-border-subtle py-3.5"
            >
              <RadioGroupItem
                id={id}
                value={preset.name}
                className="mt-0.5"
                aria-describedby={`${id}-desc`}
              />
              <label htmlFor={id} className="min-w-0 flex-1 cursor-pointer">
                <span className="block text-body font-medium">{name}</span>
                {copy && (
                  <span
                    id={`${id}-desc`}
                    className="mt-0.5 block text-cap text-muted-foreground text-pretty"
                  >
                    {t(copy.desc)}
                  </span>
                )}
              </label>
            </div>
          )
        })}
      </RadioGroup>
      {current === 'custom' && (
        <div
          data-slot="settings-row"
          className="flex min-w-0 items-start gap-3 border-t border-border-subtle py-3.5"
        >
          <Check className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
          <div className="min-w-0 flex-1">
            <p className="text-body font-medium">
              {t('riskScore.settings.presets.custom', 'Custom')}
            </p>
            <p className="mt-0.5 text-cap text-muted-foreground text-pretty">
              {t('riskScore.settings.presets.customDesc', 'Manually configured values')}
            </p>
          </div>
        </div>
      )}
    </SettingsSection>
  )
}

/** The model, the ownership floor and (for the weighted models) the CTEM switch. */
export function CompositionSection({
  config,
  weighted,
  update,
}: {
  config: RiskConfig
  weighted: boolean
  update: RiskUpdate
}) {
  const { t } = useTranslation()
  const mode = config.score_composition_mode ?? 'multiply'
  const label = t('riskScore.model.label', 'Score composition')
  return (
    <SettingsSection
      framed
      id="risk-composition"
      title={label}
      description={t(
        'riskScore.settings.composition.desc',
        'How the factors combine into one score, and how findings on assets without an owner are ranked.'
      )}
    >
      <SettingsRow
        wide
        label={t('riskScore.settings.composition.model', 'Model')}
        hint={
          !weighted
            ? t(
                'riskScore.model.likelihoodImpactHint',
                'Risk = findings score × exposure % × criticality % × (1 − control reduction).'
              )
            : mode === 'amplify_headroom'
              ? t(
                  'riskScore.model.amplifyHint',
                  'Highly-exposed critical assets no longer all pin at 100. The exposure boost fills the remaining range instead of overflowing it.'
                )
              : t(
                  'riskScore.model.multiplyHint',
                  'Exposure multiplier scales the whole score. An asset without an open finding scores 0.'
                )
        }
      >
        <Select
          value={mode}
          onValueChange={(v) =>
            update((c) => ({ ...c, score_composition_mode: v as ScoreCompositionMode }))
          }
        >
          <SelectTrigger className="w-full" aria-label={label}>
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
      </SettingsRow>
      <SettingsSwitchRow
        id="floor-unowned-toggle"
        label={t('riskScore.floor.title', 'Floor unowned findings at P2')}
        hint={t(
          'riskScore.floor.desc',
          "Findings on assets with no assigned owner can't be safely deprioritized, so keep them at P2 minimum. Only ever raises P3 to P2. Off by default."
        )}
        checked={config.floor_unowned_at_p2 ?? false}
        onCheckedChange={(v) => update((c) => ({ ...c, floor_unowned_at_p2: v }))}
      />
      {weighted && (
        <SettingsSwitchRow
          id="ctem-toggle"
          label={t('riskScore.settings.ctem.title', 'CTEM bonus points')}
          hint={t(
            'riskScore.settings.ctem.switchHint',
            'Add points for internet access, personal or health data, high-risk compliance and restricted data. When off, its weight goes to the other components.'
          )}
          checked={config.ctem_points.enabled}
          onCheckedChange={(v) =>
            update((c) => ({ ...c, ctem_points: { ...c.ctem_points, enabled: v } }))
          }
        />
      )}
    </SettingsSection>
  )
}

/** A stacked bar of the four weights. */
function WeightBar({ weights, labels }: { weights: Weights; labels: Record<WeightKey, string> }) {
  return (
    <div
      role="img"
      aria-label={WEIGHT_KEYS.map((k) => `${labels[k]} ${weights[k]}%`).join(', ')}
      className="flex h-3 w-full overflow-hidden rounded-full bg-muted"
    >
      {WEIGHT_KEYS.map((k, i) =>
        weights[k] > 0 ? (
          <div
            key={k}
            className="transition-all duration-200"
            style={{ width: `${weights[k]}%`, backgroundColor: WEIGHT_COLOR[i] }}
          />
        ) : null
      )}
    </div>
  )
}

/** The four weights; moving one rebalances the others so they always add up to 100. */
export function WeightsSection({
  config,
  onWeight,
}: {
  config: RiskConfig
  onWeight: (key: WeightKey, value: number) => void
}) {
  const { t } = useTranslation()
  const labels: Record<WeightKey, string> = {
    exposure: t('riskScore.settings.weight.exposure', 'Exposure'),
    criticality: t('riskScore.settings.weight.criticality', 'Criticality'),
    findings: t('riskScore.settings.weight.findings', 'Findings'),
    ctem: t('riskScore.settings.weight.ctem', 'CTEM'),
  }
  const hints: Record<WeightKey, string> = {
    exposure: t(
      'riskScore.settings.weight.exposureTip',
      "How much the asset's network exposure (public, private, isolated) affects its risk score"
    ),
    criticality: t(
      'riskScore.settings.weight.criticalityTip',
      "How much the asset's business criticality level affects its risk score"
    ),
    findings: t(
      'riskScore.settings.weight.findingsTip',
      'How much vulnerability findings (count or severity-weighted) affect the risk score'
    ),
    ctem: t(
      'riskScore.settings.weight.ctemTip',
      'Bonus points for factors like personal data, internet access and compliance risk'
    ),
  }
  return (
    <SettingsSection
      framed
      id="risk-weights"
      title={t('riskScore.settings.weights.title', 'Component weights')}
      description={t(
        'riskScore.settings.weights.desc',
        'Adjust the weight of each factor. Weights auto-balance to 100%.'
      )}
    >
      <div className="pb-4">
        <WeightBar weights={config.weights} labels={labels} />
      </div>
      {WEIGHT_KEYS.map((k, i) => (
        <SettingsRow
          key={k}
          wide
          label={
            <span className="inline-flex items-center gap-2">
              <span
                aria-hidden
                className="size-2 shrink-0 rounded-full"
                style={{ backgroundColor: WEIGHT_COLOR[i] }}
              />
              {labels[k]}
            </span>
          }
          hint={hints[k]}
        >
          <Slider
            aria-label={labels[k]}
            value={[config.weights[k]]}
            onValueChange={([v]) => onWeight(k, v)}
            min={0}
            max={100}
            step={5}
            className="min-w-0 flex-1"
          />
          <span className="w-10 shrink-0 text-end text-body tabular-nums">
            {config.weights[k]}%
          </span>
        </SettingsRow>
      ))}
      {!config.ctem_points.enabled && config.weights.ctem > 0 && (
        <p className="border-t border-border-subtle py-3.5 text-cap text-muted-foreground">
          {t(
            'riskScore.settings.weights.ctemOff',
            'CTEM is disabled. Its weight will be redistributed to other components.'
          )}
        </p>
      )}
    </SettingsSection>
  )
}

/** Base score per exposure level, and the multiplier of the weighted models. */
export function ExposureSection({
  config,
  weighted,
  update,
}: {
  config: RiskConfig
  weighted: boolean
  update: RiskUpdate
}) {
  const { t } = useTranslation()
  const levels = [
    {
      key: 'public',
      name: t('assets.exposure.public', 'Public'),
      hint: t('riskScore.settings.exposure.publicTip', 'Directly accessible from the internet'),
    },
    {
      key: 'restricted',
      name: t('assets.exposure.restricted', 'Restricted'),
      hint: t(
        'riskScore.settings.exposure.restrictedTip',
        'Behind VPN or firewall, limited external access'
      ),
    },
    {
      key: 'private',
      name: t('assets.exposure.private', 'Private'),
      hint: t(
        'riskScore.settings.exposure.privateTip',
        'Internal network only, no external access'
      ),
    },
    {
      key: 'isolated',
      name: t('assets.exposure.isolated', 'Isolated'),
      hint: t(
        'riskScore.settings.exposure.isolatedTip',
        'Air-gapped or completely isolated from other networks'
      ),
    },
    {
      key: 'unknown',
      name: t('assets.exposure.unknown', 'Unknown'),
      hint: t('riskScore.settings.exposure.unknownTip', 'Exposure level has not been classified'),
    },
  ] as const
  const scoreLabel = t('riskScore.settings.exposure.score', 'Base score')
  const multiplierLabel = t('riskScore.settings.exposure.multiplier', 'Multiplier')
  return (
    <SettingsSection
      framed
      id="risk-exposure"
      title={
        weighted
          ? t('riskScore.settings.exposure.titleMultipliers', 'Exposure scores and multipliers')
          : t('riskScore.settings.exposure.title', 'Exposure scores')
      }
      description={
        weighted
          ? t(
              'riskScore.settings.exposure.descMultipliers',
              'Base score (0-100) and multiplier (0.1-3.0) for each exposure level. A multiplier of 1.0 means no change, above 1.0 amplifies risk, below 1.0 reduces it.'
            )
          : t('riskScore.settings.exposure.desc', 'Base score (0-100) for each exposure level')
      }
    >
      {levels.map((l) => (
        <SettingsRow key={l.key} label={l.name} hint={l.hint}>
          <div className="flex flex-wrap gap-x-4 gap-y-3">
            <NumberField
              className="w-28"
              label={scoreLabel}
              value={config.exposure_scores[l.key]}
              onChange={(v) => update(setNumber('exposure_scores', l.key, v))}
            />
            {weighted && (
              <NumberField
                className="w-28"
                label={multiplierLabel}
                value={config.exposure_multipliers[l.key]}
                onChange={(v) => update(setNumber('exposure_multipliers', l.key, v))}
                min={0.1}
                max={3}
                step={0.1}
              />
            )}
          </div>
        </SettingsRow>
      ))}
    </SettingsSection>
  )
}

/** Why the four thresholds are not in order, or null. */
export function thresholdsValid(levels: RiskConfig['risk_levels']) {
  const { critical_min, high_min, medium_min, low_min } = levels
  return critical_min > high_min && high_min > medium_min && medium_min > low_min && low_min > 0
}

/** Base score per criticality level and the minimum score of each risk level. */
export function CriticalitySection({ config, update }: { config: RiskConfig; update: RiskUpdate }) {
  const { t } = useTranslation()
  const valid = thresholdsValid(config.risk_levels)
  const errorId = 'risk-thresholds-error'
  const criticality = [
    ['critical', t('riskScore.level.critical', 'Critical')],
    ['high', t('riskScore.level.high', 'High')],
    ['medium', t('riskScore.level.medium', 'Medium')],
    ['low', t('riskScore.level.low', 'Low')],
    ['none', t('riskScore.settings.level.none', 'None')],
  ] as const
  const thresholds = [
    ['critical_min', t('riskScore.level.critical', 'Critical')],
    ['high_min', t('riskScore.level.high', 'High')],
    ['medium_min', t('riskScore.level.medium', 'Medium')],
    ['low_min', t('riskScore.level.low', 'Low')],
  ] as const
  return (
    <SettingsSection
      framed
      id="risk-criticality"
      title={t('riskScore.settings.criticality.title', 'Criticality and risk levels')}
      description={t(
        'riskScore.settings.criticality.desc',
        'Asset criticality scores and risk level threshold boundaries'
      )}
    >
      <SettingsBlock divider={false}>
        <p className="text-body font-medium">
          {t('riskScore.settings.criticality.scores', 'Criticality scores (0–100)')}
        </p>
        <div className={GRID}>
          {criticality.map(([key, name]) => (
            <NumberField
              key={key}
              label={name}
              value={config.criticality_scores[key]}
              onChange={(v) => update(setNumber('criticality_scores', key, v))}
            />
          ))}
        </div>
      </SettingsBlock>
      <SettingsBlock>
        <p className="text-body font-medium">
          {t('riskScore.settings.thresholds.title', 'Risk level thresholds (min score)')}
        </p>
        <div className={GRID}>
          {thresholds.map(([key, name]) => (
            <NumberField
              key={key}
              label={t('riskScore.settings.minLabel', '{level} (min)', { level: name })}
              value={config.risk_levels[key]}
              onChange={(v) => update(setNumber('risk_levels', key, v))}
              min={1}
              invalid={!valid}
              describedBy={valid ? undefined : errorId}
            />
          ))}
        </div>
        {!valid && (
          <p id={errorId} role="alert" className="text-cap font-medium text-destructive">
            {t(
              'riskScore.settings.thresholds.order',
              'Must be ordered: Critical > High > Medium > Low > 0'
            )}
          </p>
        )}
      </SettingsBlock>
    </SettingsSection>
  )
}

/** How findings (and, when on, CTEM points) add to a score: the weighted models only. */
export function FindingImpactSection({
  config,
  update,
}: {
  config: RiskConfig
  update: RiskUpdate
}) {
  const { t } = useTranslation()
  const impact = config.finding_impact
  const severities = [
    ['critical', t('riskScore.level.critical', 'Critical')],
    ['high', t('riskScore.level.high', 'High')],
    ['medium', t('riskScore.level.medium', 'Medium')],
    ['low', t('riskScore.level.low', 'Low')],
    ['info', t('riskScore.settings.severity.info', 'Info')],
  ] as const
  const ctem = [
    [
      'internet_accessible',
      t('riskScore.settings.ctem.internet', 'Internet accessible'),
      t(
        'riskScore.settings.ctem.internetTip',
        'Bonus points for assets directly reachable from the internet'
      ),
    ],
    [
      'pii_exposed',
      t('riskScore.settings.ctem.pii', 'PII exposed'),
      t(
        'riskScore.settings.ctem.piiTip',
        'Bonus points for assets that process or store Personally Identifiable Information'
      ),
    ],
    [
      'phi_exposed',
      t('riskScore.settings.ctem.phi', 'PHI exposed'),
      t(
        'riskScore.settings.ctem.phiTip',
        'Bonus points for assets that process or store Protected Health Information (HIPAA)'
      ),
    ],
    [
      'high_risk_compliance',
      t('riskScore.settings.ctem.compliance', 'High-risk compliance'),
      t(
        'riskScore.settings.ctem.complianceTip',
        'Bonus points for assets under high-risk compliance frameworks (PCI-DSS, SOX, etc.)'
      ),
    ],
    [
      'restricted_data',
      t('riskScore.settings.ctem.restricted', 'Restricted data'),
      t(
        'riskScore.settings.ctem.restrictedTip',
        'Bonus points for assets that handle classified or restricted data'
      ),
    ],
  ] as const
  return (
    <SettingsSection
      framed
      id="risk-impact"
      title={t('riskScore.settings.impact.title', 'Finding and CTEM impact')}
      description={t(
        'riskScore.settings.impact.desc',
        'How findings and threat exposure factors affect scores'
      )}
    >
      <SettingsRow
        wide
        label={t('riskScore.settings.finding.mode', 'Mode')}
        hint={t(
          'riskScore.settings.finding.modeHint',
          'Count-based: each finding adds fixed points. Severity-weighted: points by severity.'
        )}
      >
        <Select
          value={impact.mode}
          onValueChange={(v) =>
            update((c) => ({
              ...c,
              finding_impact: { ...c.finding_impact, mode: v as typeof impact.mode },
            }))
          }
        >
          <SelectTrigger
            className="w-full"
            aria-label={t('riskScore.settings.finding.title', 'Finding impact')}
          >
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
      </SettingsRow>
      <SettingsBlock>
        <div className={GRID}>
          {impact.mode === 'count' && (
            <NumberField
              label={t('riskScore.settings.finding.perFinding', 'Per-finding points')}
              value={impact.per_finding_points}
              onChange={(v) =>
                update((c) => ({
                  ...c,
                  finding_impact: { ...c.finding_impact, per_finding_points: v },
                }))
              }
              min={1}
              max={50}
            />
          )}
          <NumberField
            label={t('riskScore.settings.finding.cap', 'Finding cap')}
            hint={t(
              'riskScore.settings.finding.capHint',
              'Most findings counted, so one heavily scanned asset is not unfairly high.'
            )}
            value={impact.finding_cap}
            onChange={(v) =>
              update((c) => ({ ...c, finding_impact: { ...c.finding_impact, finding_cap: v } }))
            }
            min={1}
            max={100}
          />
        </div>
      </SettingsBlock>
      {impact.mode === 'severity_weighted' && (
        <SettingsBlock>
          <p className="text-body font-medium">
            {t('riskScore.settings.finding.weights', 'Severity weights (points per finding)')}
          </p>
          <div className={GRID}>
            {severities.map(([key, name]) => (
              <NumberField
                key={key}
                label={name}
                value={impact.severity_weights[key]}
                onChange={(v) =>
                  update((c) => ({
                    ...c,
                    finding_impact: {
                      ...c.finding_impact,
                      severity_weights: { ...c.finding_impact.severity_weights, [key]: v },
                    },
                  }))
                }
                max={50}
              />
            ))}
          </div>
        </SettingsBlock>
      )}
      <SettingsBlock>
        <p className="text-body font-medium">
          {t('riskScore.settings.ctem.title', 'CTEM bonus points')}
        </p>
        {config.ctem_points.enabled ? (
          <>
            <div className={GRID}>
              {ctem.map(([key, name, hint]) => (
                <NumberField
                  key={key}
                  label={name}
                  hint={hint}
                  value={config.ctem_points[key]}
                  onChange={(v) => update(setNumber('ctem_points', key, v))}
                />
              ))}
            </div>
            <p className="text-cap text-muted-foreground">
              {t(
                'riskScore.settings.ctem.additive',
                'Points are additive: an asset with several of these gets all of them.'
              )}
            </p>
          </>
        ) : (
          <p className="text-cap text-muted-foreground">
            {t(
              'riskScore.settings.ctem.off',
              'CTEM scoring is disabled. Enable to add bonus points for threat exposure factors.'
            )}
          </p>
        )}
      </SettingsBlock>
    </SettingsSection>
  )
}

/** The formula of the model in use. */
export function HowScoringWorksSection({ weighted }: { weighted: boolean }) {
  const { t } = useTranslation()
  return (
    <SettingsSection
      framed
      id="risk-how"
      title={t('riskScore.settings.how.title', 'How scoring works')}
    >
      <div className="max-w-[68ch] space-y-2 text-dense text-muted-foreground text-pretty">
        {!weighted ? (
          <>
            <p>
              {t(
                'riskScore.model.howLikelihood',
                'Risk = findings score × exposure factor × criticality factor × (1 − control reduction). The findings score grows with each open finding by severity, with diminishing returns.'
              )}
            </p>
            <p>
              {t(
                'riskScore.model.howLikelihoodZero',
                'An asset with no open finding has a risk of 0. Exposure and criticality scale risk; they are not risk on their own.'
              )}
            </p>
          </>
        ) : (
          <>
            <p>
              <strong className="font-medium text-foreground">
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
          </>
        )}
      </div>
    </SettingsSection>
  )
}

/** Queue a new score for every asset with the saved settings, and the way to the priority rules. */
export function RecalculateSection({
  dirty,
  busy,
  onRecalculate,
  showPriorityRules,
}: {
  dirty: boolean
  busy: boolean
  onRecalculate: () => void
  showPriorityRules: boolean
}) {
  const { t } = useTranslation()
  return (
    <SettingsSection
      framed
      id="risk-recalculate"
      title={t('riskScore.recalc.title', 'Recalculate scores')}
    >
      <SettingsRow
        label={t('riskScore.recalc.button', 'Recalculate all scores')}
        hint={
          dirty
            ? t('riskScore.recalc.saveFirst', 'Save changes before recalculating.')
            : t(
                'riskScore.recalc.desc',
                'Apply the saved settings to all assets. This may take a moment for large portfolios.'
              )
        }
      >
        <Button
          variant="outline"
          disabled={busy || dirty}
          onClick={onRecalculate}
          className={cn('max-w-full')}
        >
          {busy ? <Loader2 className="animate-spin" aria-hidden /> : <ArrowUpDown aria-hidden />}
          {t('riskScore.recalc.action', 'Recalculate')}
        </Button>
      </SettingsRow>
      {showPriorityRules && (
        <SettingsRow
          label={t('riskScore.settings.priorityRules', 'Priority rules')}
          hint={t(
            'riskScore.settings.priorityRulesHint',
            'Change the priority of single findings with rules. They apply on top of the score.'
          )}
        >
          <Button variant="outline" asChild>
            <Link href="/priority-rules">
              <ListOrdered aria-hidden />
              {t('riskScore.settings.priorityRulesOpen', 'Open priority rules')}
            </Link>
          </Button>
        </SettingsRow>
      )}
    </SettingsSection>
  )
}
