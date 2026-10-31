'use client'

/**
 * How this asset was found (api docs/architecture/easm.md, Discovery lineage):
 * the discovery chain from the root asset down to this one, each ancestor a
 * link, with the discovery source, tool and first-seen time, and the
 * attribution confidence. The reasons behind the confidence stay in the
 * Ownership and scope section (same data, read once); this section shows the
 * chain. An ancestor outside the viewer's data scope arrives redacted from
 * the API and reads "Hidden asset". Used by every asset detail surface (the
 * detail sheet and /assets/{id}).
 */

import { ArrowDown, EyeOff, Route } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection, ErrorState, RelativeTime } from '@/features/shared'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { cn } from '@/lib/utils'
import { useAssetAttribution } from '../hooks/use-asset-attribution'
import { useAssetLineage } from '../hooks/use-asset-lineage'
import { AssetTypeIcon, getAssetTypeLabel } from '../lib/asset-type-icon'
import {
  discoverySourceLabel,
  isLineageRoot,
  lineageEdgeLabel,
  lineageSelf,
  lineageSteps,
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
      {node.discovery_tool && (
        <Badge variant="outline" className="font-mono text-xs font-normal">
          {node.discovery_tool}
        </Badge>
      )}
    </span>
  )
}

function StepRow({ node, isSelf }: { node: AssetLineageNode; isSelf: boolean }) {
  const { t } = useTranslation()
  if (node.hidden) {
    return (
      <div
        className="flex items-center gap-2 text-muted-foreground"
        title={t('assets.lineage.hiddenHint', 'This asset is outside your data scope.')}
      >
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted">
          <EyeOff className="h-3.5 w-3.5" aria-hidden />
        </span>
        <span>{t('assets.lineage.hidden', 'Hidden asset')}</span>
      </div>
    )
  }
  return (
    <div className="flex items-start gap-2">
      <span
        className={cn(
          'flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
          isSelf ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
        )}
      >
        <AssetTypeIcon type={node.type ?? ''} className="h-3.5 w-3.5" />
      </span>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          {isSelf || !node.id ? (
            <span className="font-medium break-all">{node.name}</span>
          ) : (
            <Link
              href={assetDetailHref(node.id)}
              className="break-all underline-offset-2 hover:underline"
            >
              {node.name}
            </Link>
          )}
          <span className="text-xs text-muted-foreground">{getAssetTypeLabel(node.type)}</span>
          {isSelf && (
            <Badge variant="outline" className="text-xs font-normal">
              {t('assets.lineage.thisAsset', 'This asset')}
            </Badge>
          )}
        </div>
        {!isSelf && <MethodChips node={node} />}
      </div>
    </div>
  )
}

/** Renders one DetailSection; place it inside a <DetailSections>. */
export function AssetLineageSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { lineage, isLoading, error, mutate } = useAssetLineage(assetId)
  // The same request as the Ownership and scope section (shared cache).
  const { attribution } = useAssetAttribution(assetId)

  const self = lineageSelf(lineage)
  const steps = lineageSteps(lineage)
  const found = self?.first_seen || self?.discovered_at
  const showConfidence = !!attribution?.recorded && !attribution.human_decided

  return (
    <DetailSection title={t('assets.lineage.title', 'How this asset was found')} icon={Route}>
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
          <dl className="grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-2">
            <dt className="text-muted-foreground">{t('assets.lineage.method', 'Method')}</dt>
            <dd className="min-w-0">
              {self.discovery_source || self.discovery_tool ? (
                <MethodChips node={self} />
              ) : (
                <span className="text-muted-foreground">
                  {t('assets.lineage.methodUnknown', 'Not recorded')}
                </span>
              )}
            </dd>
            {found && (
              <>
                <dt className="text-muted-foreground">
                  {t('assets.lineage.firstFound', 'First found')}
                </dt>
                <dd className="min-w-0">
                  <RelativeTime date={found} />
                </dd>
              </>
            )}
            {showConfidence && (
              <>
                <dt className="text-muted-foreground">
                  {t('assets.lineage.confidence', 'Confidence')}
                </dt>
                <dd className="min-w-0 tabular-nums">
                  <Badge variant="secondary" className="text-xs font-normal">
                    {t('assets.attribution.confidence', '{n}% confidence', {
                      n: attribution.confidence,
                    })}
                  </Badge>
                </dd>
              </>
            )}
          </dl>

          {isLineageRoot(lineage) ? (
            <p className="text-muted-foreground">
              {t(
                'assets.lineage.root',
                'No parent asset is recorded: this asset is where discovery started (a seed, a scope entry, an import or a scan target).'
              )}
            </p>
          ) : (
            <ol
              className="space-y-1"
              aria-label={t('assets.lineage.chainLabel', 'Discovery chain')}
            >
              {lineage?.truncated && (
                <li className="text-xs text-muted-foreground">
                  {t('assets.lineage.truncated', 'Earlier steps are not shown (more than {n}).', {
                    n: lineage.max_depth,
                  })}
                </li>
              )}
              {steps.map((step) => (
                <li key={step.node.depth} className="space-y-1">
                  {step.edge && (
                    <div className="flex items-center gap-2 ps-1.5 text-xs text-muted-foreground">
                      <ArrowDown className="h-3 w-3 shrink-0" aria-hidden />
                      <span>{lineageEdgeLabel(t, step.edge)}</span>
                    </div>
                  )}
                  <StepRow node={step.node} isSelf={step.isSelf} />
                </li>
              ))}
            </ol>
          )}
        </div>
      ) : null}
    </DetailSection>
  )
}
