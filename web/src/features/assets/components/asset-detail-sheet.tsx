/**
 * Asset Detail Sheet
 *
 * Reusable sheet component for viewing asset details
 * Supports customization via render props for type-specific content
 */

'use client'

import * as React from 'react'
import { ArrowLeft, ChevronRight, FileText, Hash, Network, Pencil, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { Button } from '@/components/ui/button'
import { TabsCount } from '@/components/ui/tabs'
import { TooltipProvider } from '@/components/ui/tooltip'
import {
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailTabs,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import { AssetStatusBadge, LifecycleSnoozeMenu } from '@/features/asset-lifecycle'
import { AssetFindings } from './asset-findings'
import { AssetSoftwareTab } from '@/features/vuln-matching'
import { TimelineSection, TechnicalDetailsSection, TagsSection } from './sheet-sections'
import { AssetMergeHistory } from './asset-merge-history'
import { AssetIdentitySections } from './asset-identity-sections'
import { AssetAttributionSection } from './asset-attribution-section'
import { AssetAttributeSourcesSection } from './asset-attribute-sources-section'
import { AssetFreshnessSection } from './asset-freshness-section'
import { AssetCoverageSection } from './asset-coverage-section'
import { AssetTimeline } from './asset-timeline'
import { useTranslation } from '@/context/i18n-provider'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { RELATED_PREVIEW_ROWS, RelatedAssetsList } from './relationships/related-assets-list'
import { useRelatedAssets } from '../hooks/use-related-assets'
import { AssetRelationshipsTab } from './asset-relationships-tab'
import { AssetOwnersTab } from './asset-owners-tab'
import { AssetScanningSection } from './asset-scanning-section'
import { AssetScopeChip } from './asset-scope-chip'
import { KeyFactsSection, hasKeyFacts } from './key-facts'
import { AssetTechnologiesSection, AssetTechnologiesTab } from './technologies'
import {
  RiskSummarySection,
  OwnershipSection,
  ExposureSection,
  DiscoverySection,
  PropertiesSection,
} from './asset-overview-sections'
import { getAssetTypeLabel } from '../lib/asset-type-icon'
import { humanizePropertyKey } from '@/features/asset-types/lib/property-schema'
import { ClassificationBadges, CIABadges, ControlPlaneBadge } from './classification-badges'
import { useAssetRelationships } from '../hooks'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import type { Asset } from '../types/asset.types'

// ============================================
// Types
// ============================================

interface AssetDetailSheetProps<T extends Asset> {
  /** The asset to display (null when sheet is closed) */
  asset: T | null

  /** Whether the sheet is open */
  open: boolean

  /** Callback when open state changes */
  onOpenChange: (open: boolean) => void

  /**
   * @deprecated Ignored. The drawer header follows the sensor drawer: name,
   * state and type line, no icon tile.
   */
  icon?: React.ElementType

  /**
   * @deprecated Ignored. The header icon sits in a neutral tile; per-type
   * colours are gone (they rendered a solid white tile in dark mode).
   */
  iconColor?: string

  /** @deprecated Ignored. The sheet header no longer has a gradient. */
  gradientFrom?: string

  /** @deprecated Ignored. The sheet header no longer has a gradient. */
  gradientVia?: string

  /** Callback when Edit button is clicked */
  onEdit: () => void

  /** Callback when Delete is clicked from danger zone */
  onDelete: () => void

  /** Whether user can edit the asset (for permission gating, default: true) */
  canEdit?: boolean

  /** Whether user can delete the asset (for permission gating, default: true) */
  canDelete?: boolean

  /** Additional quick action buttons (rendered after Edit button) */
  quickActions?: React.ReactNode

  /** Custom stats section content */
  statsContent?: React.ReactNode

  /** Custom overview section content (rendered after stats) */
  overviewContent?: React.ReactNode

  /** Optional subtitle (shown below name, defaults to groupName) */
  subtitle?: string

  /** Asset type label (e.g. "Domain"). Defaults to the asset type's label. */
  assetTypeName?: string

  /** Show the Owners tab (default: true). */
  showOwnersTab?: boolean

  /**
   * Show the generic Properties section (the asset's raw `properties`).
   * Defaults to true only when the caller passes no `overviewContent`, since
   * per-type pages render their own curated metadata sections.
   */
  showProperties?: boolean

  /** Whether to show the Details tab (default: true) */
  showDetailsTab?: boolean

  /** Whether to show the Findings tab (default: true) */
  showFindingsTab?: boolean

  /** Custom tabs to insert between Overview and Findings */
  extraTabs?: Array<{
    value: string
    label: string
    content: React.ReactNode
  }>

  // ============================================
  // Relationship Props
  // ============================================
  //
  // Add / Edit / Delete are handled internally by AssetRelationshipsTab now,
  // so consumers no longer need to wire callbacks. The only callback that
  // *must* be wired by the parent is `onNavigateToAsset` — the sheet has no
  // way to swap its own selectedAsset on its own, so navigation between
  // related assets has to be lifted up to whatever owns this sheet.

  /** Whether to show relationship preview in overview tab (default: true if relationships exist) */
  showRelationshipPreview?: boolean

  /**
   * Called when the user clicks a related asset in the relationships
   * tab or the overview preview. Should swap the parent's selectedAsset
   * to the new asset. If omitted, related-asset clicks are no-ops.
   */
  onNavigateToAsset?: (assetId: string) => void

  /** Callback when tags are updated inline */
  onUpdateTags?: (tags: string[]) => Promise<void>

  /** Available tag suggestions for autocomplete */
  tagSuggestions?: string[]

  /** Clicking a tag toggles it in the list's filter (when the sheet sits on a filterable list). */
  onTagClick?: (tag: string) => void
  /** The tags the list is filtered by (shown as active). */
  activeTags?: string[]
}

// ============================================
// Helpers
// ============================================

// daysSinceLastSeen returns the whole-days difference between now and the
// asset's last-seen timestamp. Returns undefined when the timestamp is
// missing or unparseable so the badge renders its plain form rather than
// an inaccurate "stale 0d" label.
function daysSinceLastSeen(iso?: string | null): number | undefined {
  if (!iso) return undefined
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return undefined
  const diffMs = Date.now() - t
  if (diffMs < 0) return undefined
  return Math.floor(diffMs / (1000 * 60 * 60 * 24))
}

// ============================================
// Component
// ============================================

export function AssetDetailSheet<T extends Asset>({
  asset,
  open,
  onOpenChange,
  onEdit,
  onDelete,
  canEdit = true,
  canDelete = true,
  quickActions,
  statsContent,
  overviewContent,
  subtitle,
  assetTypeName: assetTypeNameProp,
  showOwnersTab = true,
  showProperties,
  showDetailsTab = true,
  showFindingsTab = true,
  extraTabs,
  // Relationship props
  showRelationshipPreview,
  onNavigateToAsset,
  onUpdateTags,
  tagSuggestions,
  onTagClick,
  activeTags,
}: AssetDetailSheetProps<T>) {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = React.useState('overview')

  // Fetch relationships only for the overview-tab preview + the tab badge
  // count. The relationships *tab* itself fetches its own copy via
  // AssetRelationshipsTab — that copy is the source of truth for the CRUD
  // dialogs. Both calls share the same SWR cache key so there is only one
  // network request in practice.
  const { relationships } = useAssetRelationships(asset?.id ?? null)
  // Grouped related assets: the overview summary, the tab and its count share
  // one request.
  const related = useRelatedAssets(asset?.id ?? null, { limit: RELATED_PREVIEW_ROWS })
  // Relations follow the relationships module, as the API does.
  const relationshipsOn = useModuleEnabled('relationships')

  // Walking a chain of related assets keeps a trail, so "back" returns to the
  // asset the walk came from. The trail ends when the sheet closes.
  const [trail, setTrail] = React.useState<Array<{ id: string; name: string }>>([])
  React.useEffect(() => {
    if (!open) setTrail([])
  }, [open])
  const goToRelated = React.useMemo(
    () =>
      onNavigateToAsset && asset
        ? (id: string) => {
            setTrail((tr) => [...tr, { id: asset.id, name: asset.name }])
            onNavigateToAsset(id)
          }
        : undefined,
    [onNavigateToAsset, asset]
  )
  const goBackTo = (index: number) => {
    const target = trail[index]
    if (!target || !onNavigateToAsset) return
    setTrail((tr) => tr.slice(0, index))
    onNavigateToAsset(target.id)
  }

  if (!asset) return null

  const assetTypeName = assetTypeNameProp ?? getAssetTypeLabel(asset.type)
  const renderProperties = showProperties ?? overviewContent === undefined

  // Control plane is a property of relationship edges, not an asset column: the
  // asset is control-plane when it is the target of an is_control_plane edge
  // (same rule as the API's is_control_plane list filter). The API never sends
  // an asset-level flag, which is why this badge never appeared before.
  const isControlPlane =
    asset.isControlPlane ||
    relationships.some((r) => r.targetAssetId === asset.id && r.isControlPlane)

  // Determine if we should show relationships
  const hasRelationships = related.total > 0 || related.hiddenCount > 0
  const shouldShowRelationshipPreview =
    relationshipsOn && (showRelationshipPreview ?? hasRelationships)

  const typeLine =
    subtitle ||
    asset.groupName ||
    [
      assetTypeName,
      asset.subType && asset.subType !== asset.type && humanizePropertyKey(asset.subType),
    ]
      .filter(Boolean)
      .join(' · ')

  const tabs: DetailTab[] = [
    { value: 'overview', label: t('assets.sheet.tab.overview', 'Overview') },
    ...(showOwnersTab ? [{ value: 'owners', label: t('assets.sheet.tab.owners', 'Owners') }] : []),
    { value: 'timeline', label: t('assetTimeline.tab', 'Timeline') },
    ...(extraTabs ?? []).map((t) => ({ value: t.value, label: t.label })),
    ...(relationshipsOn
      ? [
          {
            value: 'relationships',
            label: (
              <>
                {t('assets.sheet.tab.relations', 'Relations')}
                {related.total > 0 && <TabsCount value={related.total} />}
              </>
            ),
          },
        ]
      : []),
    // What probes fingerprinted on the asset (RFC-112), when anything.
    ...((asset.technologies?.length ?? 0) > 0
      ? [
          {
            value: 'technologies',
            label: (
              <>
                {t('assets.technologies.title', 'Technologies')}
                <TabsCount value={asset.technologies?.length ?? 0} />
              </>
            ),
          },
        ]
      : []),
    // What the asset runs and the CVEs its versions fall in (RFC-066).
    { value: 'software', label: t('assets.sheet.tab.software', 'Software') },
    ...(showFindingsTab
      ? [
          {
            value: 'findings',
            label: (
              <>
                {t('assets.sheet.tab.findings', 'Findings')}
                {asset.findingCount > 0 && <TabsCount value={asset.findingCount} />}
              </>
            ),
          },
        ]
      : []),
    ...(showDetailsTab
      ? [{ value: 'details', label: t('assets.sheet.tab.details', 'Details') }]
      : []),
  ]
  const tab = tabs.some((t) => t.value === activeTab) ? activeTab : 'overview'

  // Security and lifecycle actions go in the ⋯ menu (style contract §8).
  const menu: DetailMenuItem[] = [
    {
      label: t('assets.sheet.copyId', 'Copy ID'),
      icon: Hash,
      onSelect: () => {
        copyToClipboard(asset.id)
        toast.success(t('assets.sheet.idCopied', 'Asset ID copied'))
      },
    },
  ]
  if (canDelete) {
    menu.push({
      label: t('assets.sheet.delete', 'Delete {type}', { type: assetTypeName.toLowerCase() }),
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: onDelete,
    })
  }

  return (
    <TooltipProvider>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        panel={tab}
        header={
          <DetailHeader
            title={asset.name}
            badges={
              <>
                <AssetStatusBadge
                  status={asset.status}
                  daysSinceLastSeen={daysSinceLastSeen(asset.lastSeen)}
                />
                {/* May scans reach it now: the scope gate's own answer. */}
                <AssetScopeChip asset={asset} />
                {/* Named values, so "Internal" (network zone) never reads
                    as the opposite of "Public" (exposure). */}
                <ClassificationBadges
                  scope={asset.scope}
                  exposure={asset.exposure}
                  criticality={asset.criticality}
                  size="md"
                  showTooltips
                  labelled
                  className="flex-wrap"
                />
                {isControlPlane && <ControlPlaneBadge size="md" />}
                <CIABadges
                  confidentiality={asset.impactConfidentiality}
                  integrity={asset.impactIntegrity}
                  availability={asset.impactAvailability}
                  size="md"
                  className="flex-wrap"
                />
              </>
            }
            meta={[typeLine]}
            actions={
              <>
                {canEdit && (
                  <Button size="sm" onClick={onEdit}>
                    <Pencil className="h-4 w-4" />
                    {t('assets.sheet.edit', 'Edit')}
                  </Button>
                )}
                {quickActions}
                {/* Lifecycle snooze shows on every asset so operators can pause
                    the worker during known offline windows. */}
                <LifecycleSnoozeMenu
                  assetID={asset.id}
                  isStaleOrInactive={asset.status === 'stale' || asset.status === 'inactive'}
                />
              </>
            }
            menu={menu}
            fullPageHref={assetDetailHref(asset.id)}
            onClose={() => onOpenChange(false)}
          />
        }
        tabs={<DetailTabs tabs={tabs} value={tab} onValueChange={setActiveTab} />}
      >
        {trail.length > 0 && (
          <nav
            aria-label={t('assets.related.trail', 'Related assets you came from')}
            className="-mt-1 mb-3 flex min-w-0 flex-wrap items-center gap-1 text-xs text-muted-foreground"
          >
            <Button
              variant="ghost"
              size="sm"
              className="h-6 gap-1 px-1.5 text-xs"
              onClick={() => goBackTo(trail.length - 1)}
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
              {t('assets.related.back', 'Back')}
            </Button>
            {trail.slice(-3).map((step, i, shown) => {
              const index = trail.length - shown.length + i
              return (
                <React.Fragment key={`${step.id}-${index}`}>
                  {(i > 0 || trail.length > shown.length) && (
                    <ChevronRight className="h-3 w-3 shrink-0" aria-hidden />
                  )}
                  <button
                    type="button"
                    className="max-w-[12rem] truncate rounded hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    onClick={() => goBackTo(index)}
                  >
                    {step.name}
                  </button>
                </React.Fragment>
              )
            })}
            <ChevronRight className="h-3 w-3 shrink-0" aria-hidden />
            <span className="max-w-[12rem] truncate text-foreground" aria-current="page">
              {asset.name}
            </span>
          </nav>
        )}
        {tab === 'overview' && (
          <DetailSections>
            {/* Order follows the triage question: how risky, who owns it,
                what it is, how exposed, where it came from. */}
            {/* What it is and what runs on it, first; typed pages pass their
                own curated sections instead. */}
            {overviewContent === undefined && <KeyFactsSection asset={asset} />}

            {/* What runs on it, by category (RFC-112). */}
            <AssetTechnologiesSection
              asset={asset}
              onViewAll={() => setActiveTab('technologies')}
            />

            <RiskSummarySection
              asset={asset}
              onViewFindings={showFindingsTab ? () => setActiveTab('findings') : undefined}
            />

            {/* May scans reach it, why, and what changes that. */}
            <AssetScanningSection
              asset={asset}
              onShowDetails={showDetailsTab ? () => setActiveTab('details') : undefined}
            />

            {statsContent}

            <OwnershipSection
              asset={asset}
              onManageOwners={showOwnersTab ? () => setActiveTab('owners') : undefined}
            />

            {asset.description && (
              <DetailSection title={t('assets.sheet.description', 'Description')} icon={FileText}>
                <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
                  {asset.description}
                </p>
              </DetailSection>
            )}

            <ExposureSection asset={asset} isControlPlane={isControlPlane} />

            {overviewContent}

            <DiscoverySection asset={asset} />

            {renderProperties && (
              <PropertiesSection
                properties={asset.metadata}
                type={asset.type}
                subType={asset.subType}
                // Under the key facts the full list is the reference: named
                // "All properties" and folded until asked for.
                all={overviewContent === undefined && hasKeyFacts(asset)}
              />
            )}

            {shouldShowRelationshipPreview && (
              <DetailSection
                title={t('assets.related.title', 'Related assets')}
                icon={Network}
                count={related.total}
                actions={
                  <Button
                    variant="link"
                    size="sm"
                    className="h-auto p-0"
                    onClick={() => setActiveTab('relationships')}
                  >
                    {t('assets.related.viewAll', 'View all')}
                  </Button>
                }
              >
                <RelatedAssetsList
                  assetId={asset.id}
                  variant="summary"
                  onNavigateToAsset={goToRelated}
                  onViewAll={() => setActiveTab('relationships')}
                />
              </DetailSection>
            )}

            <TagsSection
              tags={asset.tags}
              suggestions={tagSuggestions}
              onSave={onUpdateTags}
              onTagClick={onTagClick}
              activeTags={activeTags}
            />
          </DetailSections>
        )}

        {tab === 'owners' && <AssetOwnersTab assetId={asset.id} />}

        {tab === 'timeline' && (
          <AssetTimeline assetId={asset.id} onWhy={() => setActiveTab('details')} />
        )}

        {extraTabs?.map((t) =>
          tab === t.value ? <React.Fragment key={t.value}>{t.content}</React.Fragment> : null
        )}

        {/* Self-contained: handles Add / Edit / Delete dialogs itself. The
            sheet cannot swap its own selectedAsset, so navigation between
            related assets goes to the parent. */}
        {tab === 'relationships' && relationshipsOn && (
          <AssetRelationshipsTab
            assetId={asset.id}
            sourceAsset={{
              id: asset.id,
              name: asset.name,
              type: asset.type,
              subType: asset.subType,
            }}
            onNavigateToAsset={goToRelated}
          />
        )}

        {tab === 'technologies' && <AssetTechnologiesTab assetId={asset.id} />}

        {tab === 'software' && <AssetSoftwareTab assetId={asset.id} assetType={asset.type} />}

        {tab === 'findings' && <AssetFindings assetId={asset.id} assetName={asset.name} />}

        {tab === 'details' && (
          <DetailSections>
            <AssetAttributionSection
              assetId={asset.id}
              assetName={asset.name}
              assetType={asset.type}
            />
            <AssetAttributeSourcesSection assetId={asset.id} />
            <AssetFreshnessSection assetId={asset.id} />
            <AssetCoverageSection assetId={asset.id} />
            <TimelineSection
              firstSeen={asset.firstSeen}
              lastSeen={asset.lastSeen}
              createdAt={asset.createdAt}
              updatedAt={asset.updatedAt}
            />
            <TechnicalDetailsSection
              id={asset.id}
              type={asset.type}
              groupId={asset.groupId}
              subType={asset.subType}
              provider={asset.provider}
              externalId={asset.externalId}
              parentId={asset.parentId}
            />
            <AssetIdentitySections
              assetId={asset.id}
              assetName={asset.name}
              properties={asset.metadata}
            />
            <AssetMergeHistory assetId={asset.id} assetName={asset.name} />
          </DetailSections>
        )}
      </DetailSheet>
    </TooltipProvider>
  )
}
