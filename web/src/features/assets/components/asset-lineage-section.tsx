'use client'

/**
 * How we found this asset (api docs/architecture/easm.md, Discovery lineage,
 * and docs/architecture/exploration.md): the discovery method, first-seen
 * time and attribution confidence, then the shared story timeline: the scope
 * entry, the chain from the root asset down to this one, the run that
 * derived it, the upload that created it and the latest run that scanned it,
 * each a link. The reasons behind the confidence stay in the Ownership and
 * scope section (same data, read once). A step outside the viewer's data
 * scope or permissions reads "A step you cannot see". Used by every asset
 * detail surface (the detail sheet and /assets/{id}).
 */

import { Route } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { SignalChip } from '@/components/ui/signal-chip'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection, ErrorState, KeyValueList, RelativeTime } from '@/features/shared'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { StoryTimeline } from '@/features/exploration/components/story-timeline'
import { useStory } from '@/features/exploration/hooks/use-story'
import { useAssetAttribution } from '../hooks/use-asset-attribution'
import { useAssetLineage } from '../hooks/use-asset-lineage'
import {
  discoverySourceLabel,
  isLineageRoot,
  lineageSelf,
  type AssetLineageNode,
} from '../lib/asset-lineage'

/** Source and tool chips of one node; nothing when neither is known. */
function MethodChips({ node }: { node: AssetLineageNode }) {
  const { t } = useTranslation()
  if (!node.discovery_source && !node.discovery_tool) return null
  return (
    <span className="flex flex-wrap items-center gap-1">
      {node.discovery_source && (
        <Badge variant="secondary" className="text-xs font-normal">
          {discoverySourceLabel(t, node.discovery_source)}
        </Badge>
      )}
      {node.discovery_tool && <SignalChip>{node.discovery_tool}</SignalChip>}
    </span>
  )
}

/** Renders one DetailSection; place it inside a <DetailSections>. */
export function AssetLineageSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { lineage, isLoading, error, mutate } = useAssetLineage(assetId)
  useSettleSignal(isLoading)
  // The same request as the Ownership and scope section (shared cache).
  const { attribution } = useAssetAttribution(assetId)

  // The chain itself (scope entry, ancestors, the runs and the upload that
  // found the asset) is the shared story timeline.
  const { story, isLoading: storyLoading } = useStory('asset', assetId)
  useSettleSignal(storyLoading)
  const self = lineageSelf(lineage)
  const found = self?.first_seen || self?.discovered_at
  const showConfidence = !!attribution?.recorded && !attribution.human_decided

  return (
    <DetailSection title={t('exploration.story.title', 'How we found this')} icon={Route}>
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-5 w-2/3" />
        </div>
      ) : error ? (
        <ErrorState
          title={t('assets.lineage.errorTitle', 'discovery lineage')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : self ? (
        <div className="space-y-4 text-sm">
          <KeyValueList
            items={[
              {
                key: 'method',
                label: t('assets.lineage.method', 'Method'),
                value:
                  self.discovery_source || self.discovery_tool ? (
                    <MethodChips node={self} />
                  ) : (
                    <span className="text-muted-foreground">
                      {t('assets.lineage.methodUnknown', 'Not recorded')}
                    </span>
                  ),
              },
              ...(found
                ? [
                    {
                      key: 'found',
                      label: t('assets.lineage.firstFound', 'First found'),
                      value: <RelativeTime date={found} />,
                    },
                  ]
                : []),
              ...(showConfidence
                ? [
                    {
                      key: 'confidence',
                      label: t('assets.lineage.confidence', 'Confidence'),
                      value: (
                        <Badge variant="secondary" className="text-xs font-normal tabular-nums">
                          {t('assets.attribution.confidence', '{n}% confidence', {
                            n: attribution.confidence,
                          })}
                        </Badge>
                      ),
                    },
                  ]
                : []),
            ]}
          />

          {isLineageRoot(lineage) && (
            <p className="text-muted-foreground">
              {t(
                'assets.lineage.root',
                'No parent asset is recorded: this asset is where discovery started (a seed, a scope entry, an import or a scan target).'
              )}
            </p>
          )}
          {storyLoading ? (
            <Skeleton className="h-5 w-2/3" />
          ) : story ? (
            <StoryTimeline story={story} />
          ) : null}
        </div>
      ) : null}
    </DetailSection>
  )
}
