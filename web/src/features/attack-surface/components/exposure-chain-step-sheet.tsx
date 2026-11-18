'use client'

/**
 * The detail of one step of an exposure chain, opened over the page from a
 * chain node (the graph-page rule: a node opens its detail, it does not
 * navigate). It shows what the chains response already carries for the step:
 * nothing more is read. "View findings" is its way on; "Open attack paths"
 * follows every route to the chain's target.
 */
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { GraphNodeSheet } from '@/components/graph-page/graph-page'
import { KeyValueList, type KeyValueItem } from '@/features/shared'
import { safeInternalHref } from '@/lib/safe-href'
import { useAttackPathLabels } from './attack-path-labels'
import type { PathGraphPath } from './path-graph'

export function ExposureChainStepSheet({
  open,
  onOpenChange,
  path,
  index,
  returnFocus,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The chain and the step's place in it; kept while the sheet closes. */
  path: PathGraphPath | null
  index: number
  returnFocus?: () => HTMLElement | null
}) {
  const { t } = useTranslation()
  const labels = useAttackPathLabels()
  const node = path?.nodes[index]
  if (!path || !node) return null
  const role = labels.role({ role: node.role, isCrownJewel: node.isCrownJewel === true })
  const findingsHref = safeInternalHref(node.href)
  const pathsHref = safeInternalHref(path.detailHref)
  const items: KeyValueItem[] = [
    { key: 'role', label: t('prioritization.attackPath.node.role', 'Role'), value: role },
    {
      key: 'step',
      label: t('prioritization.exposureChains.step', 'Step'),
      value: (
        <span className="tabular-nums">
          {t('prioritization.exposureChains.stepOf', '{n} of {of}', {
            n: index + 1,
            of: path.nodes.length,
          })}
        </span>
      ),
    },
    {
      key: 'type',
      label: t('prioritization.attackPath.node.assetType', 'Asset type'),
      value: labels.assetType(node.assetType),
    },
    ...(node.exposure
      ? [
          {
            key: 'exposure',
            label: t('prioritization.attackPath.node.exposure', 'Exposure'),
            value: labels.exposure(node.exposure),
          },
        ]
      : []),
    ...(node.criticality
      ? [
          {
            key: 'criticality',
            label: t('prioritization.attackPath.node.criticality', 'Criticality'),
            value: labels.criticality(node.criticality),
          },
        ]
      : []),
    ...(node.role === 'target'
      ? [
          {
            key: 'kev',
            label: t('prioritization.attackPath.node.kevFindings', 'Known exploited'),
            value: <span className="tabular-nums">{path.kevCount ?? 0}</span>,
          },
          {
            key: 'critical',
            label: t('prioritization.exposureChains.criticalFindings', 'Critical findings'),
            value: <span className="tabular-nums">{path.criticalCount ?? 0}</span>,
          },
        ]
      : []),
  ]
  return (
    <GraphNodeSheet
      open={open}
      onOpenChange={onOpenChange}
      returnFocus={returnFocus}
      testId="exposure-chain-step-sheet"
      title={node.name}
      description={role}
      action={
        findingsHref ? (
          <Button asChild>
            <Link href={findingsHref} data-testid="chain-step-findings">
              {t('prioritization.exposureChains.viewFindings', 'View findings')}
            </Link>
          </Button>
        ) : undefined
      }
      footer={
        pathsHref ? (
          <Button asChild variant="outline">
            <Link href={pathsHref}>
              {t('prioritization.pathGraph.openPaths', 'Open attack paths')}
            </Link>
          </Button>
        ) : undefined
      }
    >
      <KeyValueList items={items} />
    </GraphNodeSheet>
  )
}
