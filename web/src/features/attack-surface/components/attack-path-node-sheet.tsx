'use client'

/**
 * The detail of one step of an attack path, opened over the page from the
 * graph (click, Enter) or the list. It shows what the path response already
 * carries for the step: nothing more is read, and a step outside the viewer's
 * data scope shows only that it is hidden.
 */

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { KevBadge } from '@/components/ui/kev-badge'
import { useTranslation } from '@/context/i18n-provider'
import { GraphNodeSheet } from '@/components/graph-page/graph-page'
import { KeyValueList, type KeyValueItem } from '@/features/shared'
import type { AttackPathDetail, PathNode } from '../hooks/use-attack-path-detail'
import { assetFindingsHref, chokeRows, formatWeight, stepText } from '../lib/attack-path-model'

export interface AttackPathNodeSheetProps {
  detail: AttackPathDetail
  open: boolean
  /** The step to show; it stays while the sheet closes. */
  node: PathNode | null
  /** Routes shown that run through the step, and how many are shown. */
  through: number
  shownTotal: number
  onOpenChange: (open: boolean) => void
  /** Light the routes through the step on the graph and close. */
  onHighlight?: () => void
  /** The node or row to focus again when the sheet closes. */
  returnFocus?: () => HTMLElement | null
}

export function AttackPathNodeSheet({
  open,
  detail,
  node,
  through,
  shownTotal,
  onOpenChange,
  onHighlight,
  returnFocus,
}: AttackPathNodeSheetProps) {
  const { t } = useTranslation()
  if (!node) return null

  const roleLabel = node.isCrownJewel
    ? t('prioritization.attackPath.role.crownJewel', 'Crown jewel')
    : t(`prioritization.attackPath.role.${node.role}`, node.role)
  const choke = chokeRows(detail).find((r) => r.key === node.key)

  const items: KeyValueItem[] = node.hidden
    ? []
    : [
        { key: 'role', label: t('prioritization.attackPath.node.role', 'Role'), value: roleLabel },
        ...(node.assetType
          ? [
              {
                key: 'type',
                label: t('prioritization.attackPath.node.assetType', 'Asset type'),
                value: node.assetType,
              },
            ]
          : []),
        ...(node.exposure
          ? [
              {
                key: 'exposure',
                label: t('prioritization.attackPath.node.exposure', 'Exposure'),
                value: node.exposure,
              },
            ]
          : []),
        ...(node.criticality
          ? [
              {
                key: 'criticality',
                label: t('prioritization.attackPath.node.criticality', 'Criticality'),
                value: node.criticality,
              },
            ]
          : []),
        {
          key: 'weight',
          label: t('prioritization.attackPath.node.weight', 'Step likelihood'),
          value: (
            <span className="tabular-nums">
              {formatWeight(node.weight)}
              {node.basis && (
                <span className="text-muted-foreground">
                  {' '}
                  ({t(`prioritization.attackPath.basis.${node.basis}`, node.basis)})
                </span>
              )}
            </span>
          ),
        },
        {
          key: 'step',
          label: t('prioritization.attackPath.node.step', 'Likeliest finding'),
          value: node.finding ? (
            <span className="flex flex-wrap items-center gap-2">
              <Link
                href={`/findings/${encodeURIComponent(node.finding.id)}`}
                className="text-signal-text hover:underline"
              >
                {node.finding.title || stepText(node)}
              </Link>
              {node.finding.kev && <KevBadge />}
            </span>
          ) : (
            t('prioritization.attackPath.basis.assumed', 'Assumed, no open finding')
          ),
        },
        {
          key: 'open',
          label: t('prioritization.attackPath.node.openFindings', 'Open findings'),
          value: <span className="tabular-nums">{node.openFindings}</span>,
        },
        {
          key: 'kev',
          label: t('prioritization.attackPath.node.kevFindings', 'Known exploited'),
          value: <span className="tabular-nums">{node.kevFindings}</span>,
        },
        {
          key: 'through',
          label: t('prioritization.attackPath.node.paths', 'Paths through it'),
          value: (
            <span className="tabular-nums">
              {t('prioritization.attackPath.node.pathsOf', '{n} of {of} shown', {
                n: through,
                of: shownTotal,
              })}
            </span>
          ),
        },
        ...(choke
          ? [
              {
                key: 'choke',
                label: t('prioritization.attackPath.chokeTitle', 'Choke points'),
                value: t('prioritization.attackPath.chokeCut', 'Cuts {n} of {of} paths', {
                  n: choke.breaks,
                  of: choke.of,
                }),
              },
            ]
          : []),
      ]

  return (
    <GraphNodeSheet
      open={open}
      returnFocus={returnFocus}
      onOpenChange={onOpenChange}
      testId="attack-path-node-sheet"
      title={node.hidden ? t('prioritization.attackPath.hidden', 'Outside your access') : node.name}
      description={
        node.hidden
          ? t('prioritization.attackPath.hiddenDetail', 'No details in your scope')
          : roleLabel
      }
      action={
        !node.hidden && node.assetId ? (
          <Button asChild>
            <Link href={assetFindingsHref(node.assetId)} data-testid="node-sheet-findings">
              {node.openFindings === 1
                ? t('prioritization.attackPath.viewOneFinding', 'View 1 finding')
                : t('prioritization.attackPath.viewFindings', 'View {n} findings', {
                    n: node.openFindings,
                  })}
            </Link>
          </Button>
        ) : undefined
      }
      footer={
        onHighlight ? (
          <Button type="button" variant="outline" onClick={onHighlight}>
            {t('prioritization.attackPath.node.highlight', 'Show its paths on the graph')}
          </Button>
        ) : undefined
      }
    >
      {node.hidden ? (
        <p className="text-body text-muted-foreground">
          {t(
            'prioritization.attackPath.node.hiddenBody',
            'This step is an asset you are not allowed to see. The path through it is real; ask an administrator for access to see the step.'
          )}
        </p>
      ) : (
        <KeyValueList items={items} />
      )}
    </GraphNodeSheet>
  )
}
