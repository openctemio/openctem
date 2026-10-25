/**
 * Classification Badges
 *
 * Visual badges for Asset Scope and Exposure Level classification
 */

'use client'

import * as React from 'react'
import {
  Globe,
  Building2,
  Cloud,
  Users,
  Store,
  HelpCircle,
  EyeOff,
  Lock,
  Shield,
  Network,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { Tag } from '@/components/ui/tag'
import { ToneChip, type Tone } from '@/components/ui/tone-chip'
import type { LucideIcon } from 'lucide-react'
import { IMPACT_RATING_LEVEL } from '@/lib/impact-colors'
import type { AssetScope, ExposureLevel, Criticality, ImpactRating } from '../types'
import {
  ASSET_SCOPE_LABELS,
  ASSET_SCOPE_DESCRIPTIONS,
  EXPOSURE_LEVEL_LABELS,
  EXPOSURE_LEVEL_DESCRIPTIONS,
  CRITICALITY_LABELS,
  CRITICALITY_DESCRIPTIONS,
  IMPACT_RATING_LABELS,
} from '../types'

// Scope, exposure, CIA and control-plane are descriptive, not a risk scale, so
// they render as neutral outline badges (icon + label). Criticality and CIA
// impact are ordinal Tag levels (bars + word), never a severity hue.
const NEUTRAL_BADGE = 'gap-1 border font-medium text-foreground'
const NEUTRAL_ICON = 'text-muted-foreground'

function sizeClass(size: 'sm' | 'md') {
  return size === 'sm' ? 'text-xs px-1.5 py-0' : 'text-xs px-2 py-0.5'
}

// Scope icons
const SCOPE_ICONS: Record<AssetScope, React.ElementType> = {
  internal: Building2,
  external: Globe,
  cloud: Cloud,
  partner: Users,
  vendor: Store,
  shadow: HelpCircle,
}

// Exposure: how reachable the asset is, in the attention tones (research/266).
// Public is the one that needs a look; unknown has a dashed edge.
const EXPOSURE_ICONS: Record<ExposureLevel, LucideIcon> = {
  public: Globe,
  restricted: Lock,
  private: EyeOff,
  isolated: Shield,
  unknown: HelpCircle,
}

export const EXPOSURE_TONE: Record<ExposureLevel, Tone> = {
  public: 'caution',
  restricted: 'neutral',
  private: 'quiet',
  isolated: 'quiet',
  unknown: 'quiet',
}

/** Criticality as a Tag level: Critical is bold with four bars, none has no bars. */
export const CRITICALITY_LEVEL: Record<Criticality, 0 | 1 | 2 | 3 | 4> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
}

interface AssetScopeBadgeProps {
  /** Prefix the value with what it is ("Zone: Internal"), for headers. */
  labelled?: boolean
  scope: AssetScope
  showIcon?: boolean
  showTooltip?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export function AssetScopeBadge({
  scope,
  showIcon = true,
  showTooltip = true,
  size = 'md',
  className,
  labelled = false,
}: AssetScopeBadgeProps) {
  const { t } = useTranslation()
  const Icon = SCOPE_ICONS[scope]
  const label = t(`assets.zone.${scope}`, ASSET_SCOPE_LABELS[scope])
  // The field is called `scope` in the API, but it is the network zone the
  // asset sits in, not whether scans may reach it (research 129, A4).
  const description = `${t(`assets.zone.${scope}.hint`, ASSET_SCOPE_DESCRIPTIONS[scope])} ${t(
    'assets.zone.notScanScope',
    'This is the network zone, not the scan scope.'
  )}`
  const prefix = labelled ? t('assets.badge.zone', 'Zone') : null

  const badge = (
    <Badge variant="outline" className={cn(NEUTRAL_BADGE, sizeClass(size), className)}>
      {showIcon && <Icon className={cn(NEUTRAL_ICON, size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5')} />}
      {prefix && <span className="font-normal opacity-75">{prefix}:</span>}
      {label}
    </Badge>
  )

  if (!showTooltip) return badge

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>{badge}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-[200px]">
          <p className="font-medium">{label}</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

interface ExposureBadgeProps {
  /** Prefix the value with what it is ("Zone: Internal"), for headers. */
  labelled?: boolean
  exposure: ExposureLevel
  showIcon?: boolean
  showTooltip?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export function ExposureBadge({
  exposure,
  showIcon = true,
  showTooltip = true,
  size = 'md',
  className,
  labelled = false,
}: ExposureBadgeProps) {
  const { t } = useTranslation()
  const Icon = EXPOSURE_ICONS[exposure]
  const label = t(`assets.exposure.${exposure}`, EXPOSURE_LEVEL_LABELS[exposure])
  const description = t(`assets.exposure.${exposure}.hint`, EXPOSURE_LEVEL_DESCRIPTIONS[exposure])
  const prefix = labelled ? t('assets.badge.exposure', 'Exposure') : null

  const badge = (
    <span className="inline-flex" data-slot="exposure-badge" data-exposure={exposure}>
      <ToneChip
        tone={EXPOSURE_TONE[exposure] ?? 'quiet'}
        icon={showIcon ? Icon : undefined}
        dashed={exposure === 'unknown'}
        value={exposure}
        label={prefix ? `${prefix}: ${label}` : label}
        title={showTooltip ? undefined : label}
        className={cn(size === 'sm' && 'h-5', className)}
      />
    </span>
  )

  if (!showTooltip) return badge

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>{badge}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-[200px]">
          <p className="font-medium">{label}</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

interface CriticalityBadgeProps {
  /** Prefix the value with what it is ("Zone: Internal"), for headers. */
  labelled?: boolean
  criticality: Criticality
  showIcon?: boolean
  showTooltip?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export function CriticalityBadge({
  criticality,
  showIcon = true,
  showTooltip = true,
  size = 'md',
  className,
  labelled = false,
}: CriticalityBadgeProps) {
  const { t } = useTranslation()
  const label = t(`criticality.${criticality}`, CRITICALITY_LABELS[criticality])
  const description = t(`criticality.${criticality}.hint`, CRITICALITY_DESCRIPTIONS[criticality])
  const prefix = labelled ? t('assets.badge.criticality', 'Criticality') : null

  // An ordinal classification, not a severity: four bars and the word. The
  // icon prop is kept for callers; the bars are the glyph.
  const badge = (
    <span className="inline-flex" data-slot="criticality-badge" data-criticality={criticality}>
      <Tag
        level={CRITICALITY_LEVEL[criticality]}
        label={prefix ? `${prefix}: ${label}` : label}
        title={showTooltip ? undefined : label}
        className={cn(size === 'sm' && 'h-5', className)}
      />
    </span>
  )

  if (!showTooltip) return badge

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>{badge}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-[200px]">
          <p className="font-medium">{label}</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

interface ClassificationBadgesProps {
  scope: AssetScope
  exposure: ExposureLevel
  criticality?: Criticality
  showIcons?: boolean
  showTooltips?: boolean
  size?: 'sm' | 'md'
  className?: string
  /** Header use: name each value ("Criticality: High", "Exposure: Public", "Zone: Internal"). */
  labelled?: boolean
}

/**
 * Combined component showing scope, exposure, and optionally criticality badges.
 *
 * The exposure badge is hidden when the value is "unknown" (the default for
 * assets created without an explicit exposure level). Showing a row of grey
 * "Unknown" pills next to every asset adds noise without information — once a
 * real exposure level is set the badge will appear automatically.
 */
export function ClassificationBadges({
  scope,
  exposure,
  criticality,
  showIcons = true,
  showTooltips = true,
  size = 'md',
  className,
  labelled = false,
}: ClassificationBadgesProps) {
  const showExposure = exposure && exposure !== 'unknown'
  // Every asset starts in zone "internal" (the stored default) until a person
  // or an integration sets it, so in a header "Zone: Internal" carries no
  // information and, next to "Exposure: Public" on a discovered website,
  // reads as a contradiction. The header shows the zone only when it is not
  // the default.
  const showZone = !!scope && !(labelled && scope === 'internal')
  const zone = showZone ? (
    <AssetScopeBadge
      scope={scope}
      showIcon={showIcons}
      showTooltip={showTooltips}
      size={size}
      labelled={labelled}
    />
  ) : null
  return (
    <div className={cn('flex items-center gap-1.5', className)}>
      {criticality && (
        <CriticalityBadge
          criticality={criticality}
          showIcon={showIcons}
          showTooltip={showTooltips}
          size={size}
          labelled={labelled}
        />
      )}
      {/* A header reads what matters first: criticality, exposure, then the zone. */}
      {!labelled && zone}
      {showExposure && (
        <ExposureBadge
          exposure={exposure}
          showIcon={showIcons}
          showTooltip={showTooltips}
          size={size}
          labelled={labelled}
        />
      )}
      {labelled && zone}
    </div>
  )
}

const CIA_DIMENSIONS = [
  {
    key: 'confidentiality',
    letter: 'C',
    label: 'Confidentiality',
    consequence: 'Business impact if unauthorized disclosure occurred.',
  },
  {
    key: 'integrity',
    letter: 'I',
    label: 'Integrity',
    consequence: 'Business impact if unauthorized modification occurred.',
  },
  {
    key: 'availability',
    letter: 'A',
    label: 'Availability',
    consequence: 'Business impact if loss of access or uptime occurred.',
  },
] as const

interface CIABadgesProps {
  confidentiality?: ImpactRating
  integrity?: ImpactRating
  availability?: ImpactRating
  size?: 'sm' | 'md'
  className?: string
}

/**
 * Compact read-only display of the CTEM Scoping CIA business-impact ratings
 * (api #467). Each set dimension renders as a small `C:High` style pill; unset
 * dimensions are omitted. Renders nothing when no dimension is rated, so it can
 * be dropped in unconditionally.
 */
export function CIABadges({
  confidentiality,
  integrity,
  availability,
  size = 'md',
  className,
}: CIABadgesProps) {
  const { t } = useTranslation()
  const values: Record<string, ImpactRating | undefined> = {
    confidentiality,
    integrity,
    availability,
  }
  const rated = CIA_DIMENSIONS.filter((d) => values[d.key])
  if (rated.length === 0) return null

  return (
    <TooltipProvider>
      <div className={cn('flex items-center gap-1.5', className)}>
        {rated.map((d) => {
          const rating = values[d.key] as ImpactRating
          return (
            <Tooltip key={d.key} delayDuration={200}>
              <TooltipTrigger asChild>
                <span className="inline-flex">
                  <Tag
                    level={IMPACT_RATING_LEVEL[rating]}
                    label={`${d.letter} ${t(`assets.cia.rating.${rating}`, IMPACT_RATING_LABELS[rating])}`}
                    title=""
                    className={cn(size === 'sm' && 'h-5')}
                  />
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-[220px]">
                <p className="font-medium">
                  {t('assets.cia.tooltipTitle', '{dimension}: {rating} impact', {
                    dimension: t(`assets.cia.${d.key}`, d.label),
                    rating: t(`assets.cia.rating.${rating}`, IMPACT_RATING_LABELS[rating]),
                  })}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t(`assets.cia.${d.key}.consequence`, d.consequence)}
                </p>
              </TooltipContent>
            </Tooltip>
          )
        })}
      </div>
    </TooltipProvider>
  )
}

interface ControlPlaneBadgeProps {
  size?: 'sm' | 'md'
  showTooltip?: boolean
  className?: string
}

/**
 * Read-only badge marking an asset as part of the control plane
 * (assets.is_control_plane) — infrastructure that governs other assets
 * (identity providers, orchestrators, CI/CD, secret stores). Compromise here
 * has an outsized blast radius, so the CTEM register tracks it explicitly.
 * Render only when the flag is true.
 */
export function ControlPlaneBadge({
  size = 'md',
  showTooltip = true,
  className,
}: ControlPlaneBadgeProps) {
  const { t } = useTranslation()
  const badge = (
    <Badge variant="outline" className={cn(NEUTRAL_BADGE, sizeClass(size), className)}>
      <Network className={cn(NEUTRAL_ICON, size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5')} />
      {t('assets.cia.controlPlane', 'Control plane')}
    </Badge>
  )

  if (!showTooltip) return badge

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>{badge}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-[220px]">
          <p className="font-medium">{t('assets.cia.controlPlaneTitle', 'Control-plane asset')}</p>
          <p className="text-xs text-muted-foreground">
            {t(
              'assets.cia.controlPlaneHint',
              'Governs other assets (identity, orchestration, CI/CD, secrets). Elevated blast radius if compromised.'
            )}
          </p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
