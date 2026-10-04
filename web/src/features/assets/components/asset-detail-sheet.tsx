/**
 * Asset Detail Sheet
 *
 * Reusable sheet component for viewing asset details
 * Supports customization via render props for type-specific content
 */

'use client'

import * as React from 'react'
import { FileText, Hash, Pencil, Radar, Trash2 } from 'lucide-react'
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
import { TimelineSection, TechnicalDetailsSection, TagsSection } from './sheet-sections'
import { AssetMergeHistory } from './asset-merge-history'
import { AssetIdentitySections } from './asset-identity-sections'
import { AssetAttributionSection } from './asset-attribution-section'
import { RelationshipPreview } from './relationships'
import { AssetRelationshipsTab } from './asset-relationships-tab'
import { AssetOwnersTab } from './asset-owners-tab'
import { SurfaceFactsDetail, cellsForType } from './service-cells'
import {
  RiskSummarySection,
  OwnershipSection,
  ExposureSection,
  DiscoverySection,
  PropertiesSection,
} from './asset-overview-sections'
import { getAssetTypeLabel } from '../lib/asset-type-icon'
import { ClassificationBadges, CIABadges, ControlPlaneBadge } from './classification-badges'
import { useAssetRelationships } from '../hooks'
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
}: AssetDetailSheetProps<T>) {
  const [activeTab, setActiveTab] = React.useState('overview')

  // Fetch relationships only for the overview-tab preview + the tab badge
  // count. The relationships *tab* itself fetches its own copy via
  // AssetRelationshipsTab — that copy is the source of truth for the CRUD
  // dialogs. Both calls share the same SWR cache key so there is only one
  // network request in practice.
  const { relationships } = useAssetRelationships(asset?.id ?? null)

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
  const hasRelationships = relationships.length > 0
  const shouldShowRelationshipPreview = showRelationshipPreview ?? hasRelationships

  const typeLine =
    subtitle ||
    asset.groupName ||
    [assetTypeName, asset.subType && asset.subType !== asset.type && asset.subType]
      .filter(Boolean)
      .join(' · ')

  const tabs: DetailTab[] = [
    { value: 'overview', label: 'Overview' },
    ...(showOwnersTab ? [{ value: 'owners', label: 'Owners' }] : []),
    ...(extraTabs ?? []).map((t) => ({ value: t.value, label: t.label })),
    {
      value: 'relationships',
      label: (
        <>
          Relations
          {relationships.length > 0 && <TabsCount value={relationships.length} />}
        </>
      ),
    },
    ...(showFindingsTab
      ? [
          {
            value: 'findings',
            label: (
              <>
                Findings
                {asset.findingCount > 0 && <TabsCount value={asset.findingCount} />}
              </>
            ),
          },
        ]
      : []),
    ...(showDetailsTab ? [{ value: 'details', label: 'Details' }] : []),
  ]
  const tab = tabs.some((t) => t.value === activeTab) ? activeTab : 'overview'

  // Security and lifecycle actions go in the ⋯ menu (style contract §8).
  const menu: DetailMenuItem[] = [
    {
      label: 'Copy ID',
      icon: Hash,
      onSelect: () => {
        copyToClipboard(asset.id)
        toast.success('Asset ID copied')
      },
    },
  ]
  if (canDelete) {
    menu.push({
      label: `Delete ${assetTypeName.toLowerCase()}`,
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
                {/* Classification and the CTEM scoping signals (control-plane
                    flag, CIA business-impact ratings), api #467. */}
                <ClassificationBadges
                  scope={asset.scope}
                  exposure={asset.exposure}
                  criticality={asset.criticality}
                  size="md"
                  showTooltips
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
                    Edit
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
            onClose={() => onOpenChange(false)}
          />
        }
        tabs={<DetailTabs tabs={tabs} value={tab} onValueChange={setActiveTab} />}
      >
        {tab === 'overview' && (
          <DetailSections>
            {/* Order follows the triage question: how risky, who owns it,
                what it is, how exposed, where it came from. */}
            <RiskSummarySection
              asset={asset}
              onViewFindings={showFindingsTab ? () => setActiveTab('findings') : undefined}
            />

            {statsContent}

            <OwnershipSection
              asset={asset}
              onManageOwners={showOwnersTab ? () => setActiveTab('owners') : undefined}
            />

            {asset.description && (
              <DetailSection title="Description" icon={FileText}>
                <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
                  {asset.description}
                </p>
              </DetailSection>
            )}

            <ExposureSection asset={asset} isControlPlane={isControlPlane} />

            {overviewContent}

            <DiscoverySection asset={asset} />

            {/* The typed pages pass their own curated sections; the mixed
                lists (/assets) get the shared service cells for the
                external-surface types, above the raw properties: the known
                facts, then one "Not collected yet: …" line for the rest. */}
            {overviewContent === undefined && cellsForType(asset.type, asset.subType) && (
              <DetailSection title="Service facts" icon={Radar}>
                <SurfaceFactsDetail asset={asset} />
              </DetailSection>
            )}

            {renderProperties && <PropertiesSection properties={asset.metadata} />}

            {shouldShowRelationshipPreview && (
              <RelationshipPreview
                relationships={relationships}
                currentAssetId={asset.id}
                onViewAll={() => setActiveTab('relationships')}
                onAssetClick={onNavigateToAsset}
                maxItems={3}
              />
            )}

            <TagsSection tags={asset.tags} suggestions={tagSuggestions} onSave={onUpdateTags} />
          </DetailSections>
        )}

        {tab === 'owners' && <AssetOwnersTab assetId={asset.id} />}

        {extraTabs?.map((t) =>
          tab === t.value ? <React.Fragment key={t.value}>{t.content}</React.Fragment> : null
        )}

        {/* Self-contained: handles Add / Edit / Delete dialogs itself. The
            sheet cannot swap its own selectedAsset, so navigation between
            related assets goes to the parent. */}
        {tab === 'relationships' && (
          <AssetRelationshipsTab
            assetId={asset.id}
            sourceAsset={{ id: asset.id, name: asset.name, type: asset.type }}
            onNavigateToAsset={onNavigateToAsset}
          />
        )}

        {tab === 'findings' && <AssetFindings assetId={asset.id} assetName={asset.name} />}

        {tab === 'details' && (
          <DetailSections>
            <AssetAttributionSection assetId={asset.id} />
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
