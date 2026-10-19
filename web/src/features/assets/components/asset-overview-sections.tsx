/**
 * Asset Detail Sheet - Overview sections
 *
 * The Overview tab used to render only description, owner reference and tags,
 * so most assets showed "No tags" and nothing else even though the API returns
 * risk, severity breakdown, ownership, discovery and classification data. These
 * sections render that data for every asset type; per-type pages can still add
 * their own content on top via `overviewContent`.
 */

'use client'

import * as React from 'react'
import { AlertTriangle, Gauge, ListTree, Radar, Search, ShieldHalf, UserRound } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DetailSection,
  DetailField,
  DetailFieldGrid,
  RelativeTime,
  RiskScoreBadge,
  riskScoreState,
  SeverityStrip,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import type { TFn } from '../lib/default-t'
import {
  groupProperties,
  propertyLabel,
  type PropertyEntry,
} from '@/features/asset-types/lib/property-schema'
import { PropertyValue, hasPropertyValue, isWideValue } from './property-value'
import type { Asset } from '../types/asset.types'
import { ProgramTargetBadge } from './program-target-badge'
import { AssetRiskExplanation } from './asset-risk-explanation'

// The property list gets a search box from this many values.
const SEARCH_FROM = 8

// Assets not observed for this long are flagged as possibly stale.
const STALE_AFTER_DAYS = 30

function humanize(value: string): string {
  const words = value.replace(/[-_]+/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

function daysSince(iso?: string): number | undefined {
  if (!iso) return undefined
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return undefined
  const diff = Date.now() - t
  return diff < 0 ? undefined : Math.floor(diff / 86_400_000)
}

function DateWithRelative({ iso }: { iso?: string }) {
  if (!iso) return null
  return (
    <span className="flex flex-wrap items-baseline gap-x-1.5">
      <span>{new Date(iso).toLocaleString()}</span>
      <RelativeTime date={iso} className="text-xs text-muted-foreground" />
    </span>
  )
}

// ============================================
// Risk
// ============================================

interface RiskSummarySectionProps {
  asset: Asset
  /** Switches the sheet to its Findings tab. Omit to hide the link. */
  onViewFindings?: () => void
}

/** Risk score plus the open-finding breakdown by severity. */
export function RiskSummarySection({ asset, onViewFindings }: RiskSummarySectionProps) {
  const { t } = useTranslation()
  const counts = asset.findingSeverityCounts ?? {}
  const hasFindings = asset.findingCount > 0
  const state = riskScoreState(asset)
  const [showWhy, setShowWhy] = React.useState(false)

  return (
    <DetailSection
      title={t('components.col.risk', 'Risk')}
      icon={Gauge}
      actions={
        hasFindings && onViewFindings ? (
          <Button variant="link" size="sm" className="h-auto p-0" onClick={onViewFindings}>
            {t('assets.overview2.viewFindings', 'View findings')}
          </Button>
        ) : undefined
      }
    >
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">
            {t('assets.overview2.riskScore', 'Risk score')}
          </p>
          <RiskScoreBadge score={asset.riskScore} state={state} size="md" />
          {asset.riskScoredAt && (
            <p className="flex items-baseline gap-1 text-xs text-muted-foreground">
              {t('riskScore.updated', 'Score updated')}
              <RelativeTime date={asset.riskScoredAt} className="text-xs" />
            </p>
          )}
        </div>
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">
            {t('assets.overview2.openFindings', 'Open findings')}
          </p>
          <p className="text-lg leading-none font-semibold tabular-nums">{asset.findingCount}</p>
        </div>
      </div>
      {hasFindings ? (
        <SeverityStrip counts={counts} className="mt-4" />
      ) : (
        <p className="mt-3 text-sm text-muted-foreground">
          {t('assets.overview2.noOpen', 'No open findings on this asset.')}
        </p>
      )}
      {state !== 'unscored' && state !== 'calculating' && (
        <div className="mt-3">
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            aria-expanded={showWhy}
            onClick={() => setShowWhy((v) => !v)}
          >
            {showWhy
              ? t('riskScore.why.hide', 'Hide explanation')
              : t('riskScore.why.show', 'Why this score?')}
          </Button>
          {showWhy && (
            <div className="mt-2 rounded-md border p-3">
              <AssetRiskExplanation assetId={asset.id} />
            </div>
          )}
        </div>
      )}
    </DetailSection>
  )
}

// ============================================
// Ownership
// ============================================

interface OwnershipSectionProps {
  asset: Asset
  /** Switches to the Owners tab when the sheet has one. */
  onManageOwners?: () => void
}

/**
 * Primary owner + free-text owner reference. An asset with neither is called
 * out: CTEM mobilization depends on every exposure having someone to route to.
 */
export function OwnershipSection({ asset, onManageOwners }: OwnershipSectionProps) {
  const { t } = useTranslation()
  const owner = asset.primaryOwner
  const hasOwner = !!owner || !!asset.ownerRef

  return (
    <DetailSection
      title={t('assets.overview2.ownership', 'Ownership')}
      icon={UserRound}
      actions={
        onManageOwners ? (
          <Button variant="link" size="sm" className="h-auto p-0" onClick={onManageOwners}>
            {hasOwner
              ? t('assets.overview2.manageOwners', 'Manage owners')
              : t('assets.overview2.assignOwner', 'Assign owner')}
          </Button>
        ) : undefined
      }
    >
      {hasOwner ? (
        <DetailFieldGrid>
          {owner && (
            <DetailField
              label={
                owner.type === 'group'
                  ? t('assets.overview2.owningTeam', 'Owning team')
                  : t('assets.overview2.primaryOwner', 'Primary owner')
              }
            >
              <span className="block">{owner.name}</span>
              {owner.email && (
                <span className="block text-xs text-muted-foreground">{owner.email}</span>
              )}
            </DetailField>
          )}
          <DetailField label={t('assets.overview2.ownerRef', 'Owner reference')}>
            {asset.ownerRef}
          </DetailField>
        </DetailFieldGrid>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <AlertTriangle className="h-4 w-4 shrink-0 text-warning" />
          {t(
            'assets.overview2.noOwner',
            'No owner assigned. Findings on this asset have no one to be routed to.'
          )}
        </p>
      )}
    </DetailSection>
  )
}

// ============================================
// Exposure & data
// ============================================

interface ExposureSectionProps {
  asset: Asset
  /** Derived from relationships: the asset is the target of a control-plane edge. */
  isControlPlane?: boolean
}

function yesNo(value: boolean | undefined, t: TFn): string | undefined {
  if (value === undefined) return undefined
  return value ? t('assets.overview2.yes', 'Yes') : t('assets.properties.no', 'No')
}

/** Reachability and data sensitivity: the context that weighs a finding's impact. */
export function ExposureSection({ asset, isControlPlane }: ExposureSectionProps) {
  const { t } = useTranslation()
  const sensitive = [asset.piiDataExposed && 'PII', asset.phiDataExposed && 'PHI'].filter(
    Boolean
  ) as string[]
  const sensitivityKnown = asset.piiDataExposed !== undefined || asset.phiDataExposed !== undefined

  return (
    <DetailSection
      title={t('assets.overview2.exposureData', 'Exposure and data')}
      icon={ShieldHalf}
    >
      <DetailFieldGrid>
        <DetailField label={t('assets.overview2.internetFacing', 'Internet-facing')}>
          {yesNo(asset.isInternetFacing, t)}
        </DetailField>
        <DetailField label={t('assets.overview2.networkExposure', 'Network exposure')}>
          {asset.exposure ? humanize(asset.exposure) : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.controlPlane', 'Control plane')}>
          {isControlPlane
            ? t('assets.overview2.controlPlaneYes', 'Yes, other assets depend on it for security')
            : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.crownJewel', 'Crown jewel')}>
          {asset.isCrownJewel ? t('assets.overview2.yes', 'Yes') : undefined}
        </DetailField>
        <DetailField label={t('assets.programTarget.field', 'Bug-bounty program')}>
          {asset.systemTags?.includes('bug-bounty') ? (
            <ProgramTargetBadge systemTags={asset.systemTags} programOnly={asset.programOnly} />
          ) : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.dataClass', 'Data classification')}>
          {asset.dataClassification ? humanize(asset.dataClassification) : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.sensitive', 'Sensitive data exposed')}>
          {sensitivityKnown
            ? sensitive.length
              ? sensitive.join(', ')
              : t('assets.overview2.noneFlagged', 'None flagged')
            : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.compliance', 'Compliance scope')} full>
          {asset.complianceScope?.length ? (
            <span className="flex flex-wrap gap-1">
              {asset.complianceScope.map((c) => (
                <Badge key={c} variant="outline" className="font-normal">
                  {c}
                </Badge>
              ))}
            </span>
          ) : undefined}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

// ============================================
// Discovery
// ============================================

/** Where the asset came from and how fresh the observation is. */
export function DiscoverySection({ asset }: { asset: Asset }) {
  const { t } = useTranslation()
  const staleDays = daysSince(asset.lastSeen)
  const isStale = staleDays !== undefined && staleDays >= STALE_AFTER_DAYS

  return (
    <DetailSection title={t('assets.overview2.discovery', 'Discovery')} icon={Radar}>
      <DetailFieldGrid>
        <DetailField label={t('assets.overview2.source', 'Source')}>
          {asset.discoverySource ? humanize(asset.discoverySource) : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.discoveredBy', 'Discovered by')}>
          {asset.discoveryTool}
        </DetailField>
        <DetailField label={t('assets.overview2.firstSeen', 'First seen')}>
          <DateWithRelative iso={asset.firstSeen || asset.discoveredAt} />
        </DetailField>
        <DetailField label={t('components.col.lastSeen', 'Last seen')}>
          <DateWithRelative iso={asset.lastSeen} />
        </DetailField>
        <DetailField label={t('assets.overview2.syncStatus', 'Sync status')}>
          {asset.syncStatus ? humanize(asset.syncStatus) : undefined}
        </DetailField>
        <DetailField label={t('assets.overview2.lastSynced', 'Last synced')}>
          {asset.lastSyncedAt ? <DateWithRelative iso={asset.lastSyncedAt} /> : undefined}
        </DetailField>
      </DetailFieldGrid>
      {isStale && (
        <p className="mt-3 flex items-center gap-2 text-sm text-warning">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {t(
            'assets.overview2.stale',
            'Not observed for {days} days. Its findings may be out of date; rescan to confirm.',
            { days: staleDays }
          )}
        </p>
      )}
    </DetailSection>
  )
}

// ============================================
// Properties
// ============================================

/**
 * The asset's `properties`, rendered from the property schema of its type
 * (RFC-042 §6.3.9): labels in the viewer's language and in schema order,
 * addresses linked to their IP assets, synonyms an older row still holds
 * shown once under the canonical key, and keys outside the schema
 * (third-party or custom) under "Other".
 */
export function PropertiesSection({
  properties,
  type,
  subType,
  all = false,
}: {
  properties?: Record<string, unknown>
  /** The asset's stored type and sub-type; without them every key is "Other". */
  type?: string
  subType?: string | null
  /**
   * Shown under the key facts: titled "All properties" and folded until the
   * reader opens it (the key facts already answer the first questions).
   */
  all?: boolean
}) {
  const { locale, t } = useTranslation()
  const [query, setQuery] = React.useState('')
  const [open, setOpen] = React.useState(!all)
  const { known, other } = React.useMemo(
    () => groupProperties(properties, type ?? '', subType),
    [properties, type, subType]
  )
  const label = React.useCallback((key: string) => propertyLabel(key, locale), [locale])
  const q = query.trim().toLowerCase()
  const matches = React.useCallback(
    (e: PropertyEntry) =>
      !q ||
      e.key.toLowerCase().includes(q) ||
      label(e.key).toLowerCase().includes(q) ||
      JSON.stringify(e.value ?? '')
        .toLowerCase()
        .includes(q),
    [q, label]
  )
  const knownRows = known.filter((e) => hasPropertyValue(e.value))
  const otherRows = other.filter((e) => hasPropertyValue(e.value))
  const count = knownRows.length + otherRows.length
  if (count === 0) return null
  const knownShown = knownRows.filter(matches)
  const otherShown = otherRows.filter(matches)

  const grid = (rows: PropertyEntry[]) => (
    <DetailFieldGrid>
      {rows.map((e) => (
        <DetailField key={e.key} label={label(e.key)} full={isWideValue(e.value)}>
          <PropertyValue value={e.value} format={e.format} />
        </DetailField>
      ))}
    </DetailFieldGrid>
  )

  return (
    <DetailSection
      title={
        all
          ? t('assets.properties.allTitle', 'All properties')
          : t('assets.properties.title', 'Properties')
      }
      icon={ListTree}
      count={count}
      actions={
        all ? (
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t('assets.properties.hide', 'Hide') : t('assets.properties.show', 'Show')}
          </Button>
        ) : undefined
      }
    >
      {open && count > SEARCH_FROM && (
        <div className="relative">
          <Search className="pointer-events-none absolute start-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('assets.properties.search', 'Search properties')}
            aria-label={t('assets.properties.search', 'Search properties')}
            className="h-8 ps-8 text-sm"
          />
        </div>
      )}
      {open && knownShown.length > 0 && grid(knownShown)}
      {open && otherShown.length > 0 && (
        <div className="space-y-2">
          {knownShown.length > 0 && (
            <p className="text-xs font-medium text-muted-foreground">
              {t('assets.properties.other', 'Other')}
            </p>
          )}
          {grid(otherShown)}
        </div>
      )}
      {open && knownShown.length + otherShown.length === 0 && (
        <p className="text-sm text-muted-foreground">
          {t('assets.properties.noMatch', 'No property matches "{query}".', { query })}
        </p>
      )}
    </DetailSection>
  )
}
