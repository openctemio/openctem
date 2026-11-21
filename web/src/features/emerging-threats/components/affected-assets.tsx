'use client'

/**
 * The affected hosts of an alert: one table grouped by tier (confirmed,
 * likely, possible), one row per host. A host that serves several ports has
 * one service asset per port; the API folds them into the host's row
 * (`asset_groups`) and the row lists each service with its own asset,
 * finding and task links. Server text is rendered as plain text.
 */

import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, KeyValueList, type KeyValueItem } from '@/features/shared'
import type {
  AssetTier,
  EmergingThreatAssetGroup,
  EmergingThreatHost,
  EmergingThreatHostService,
} from '../types'

const TIER_ORDER: AssetTier[] = ['confirmed', 'likely', 'possible']
const PAGE_SIZES = [25, 50, 100]

export type HostRow = EmergingThreatHost & { tier: AssetTier; key: string }

function Dash() {
  return <span className="text-muted-foreground">—</span>
}

/** The row's name: the host, and under it each service as a link to its asset. */
export function HostTitle({ row }: { row: HostRow }) {
  const { t } = useTranslation()
  const single = row.asset_id ? row.services[0] : undefined
  return (
    <div className="flex min-w-0 flex-col gap-1">
      {row.asset_id ? (
        <Link
          href={`/assets/${row.asset_id}`}
          className="font-medium [overflow-wrap:anywhere] hover:underline"
        >
          {row.host}
        </Link>
      ) : (
        <span className="font-medium [overflow-wrap:anywhere]">{row.host}</span>
      )}
      {single ? (
        <span className="text-xs text-muted-foreground">{single.asset_type}</span>
      ) : (
        <ul
          aria-label={t('emergingThreats.assets.servicesOf', undefined, { host: row.host })}
          className="flex flex-wrap gap-1.5"
        >
          {row.services.map((s) => (
            <li key={s.asset_id}>
              <Link
                href={`/assets/${s.asset_id}`}
                title={s.asset_name}
                className="inline-flex min-h-6 items-center rounded-md border px-1.5 font-mono text-xs max-md:min-h-8 max-md:px-2 [overflow-wrap:anywhere] hover:bg-muted"
              >
                {s.label}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/**
 * One link per service that has one; with several services each link is
 * preceded by its service, so none is dropped and each is told apart.
 */
function ServiceLinks({
  row,
  link,
}: {
  row: HostRow
  link: (s: EmergingThreatHostService) => React.ReactNode
}) {
  const links = row.services.flatMap((s) => {
    const node = link(s)
    return node ? [{ s, node }] : []
  })
  if (links.length === 0) return <Dash />
  const labelled = row.services.length > 1
  return (
    <ul className="flex flex-col gap-0.5">
      {links.map(({ s, node }) => (
        <li key={s.asset_id} className="flex flex-wrap items-baseline gap-x-1.5">
          {labelled && <span className="font-mono text-xs text-muted-foreground">{s.label}</span>}
          {node}
        </li>
      ))}
    </ul>
  )
}

export function AffectedAssets({
  groups,
  error,
  onRetry,
}: {
  groups: EmergingThreatAssetGroup[]
  /** The read that brings the groups failed (the alert's detail). */
  error?: unknown
  onRetry?: () => void
}) {
  const { t } = useTranslation()

  const rows = useMemo<HostRow[]>(
    () =>
      groups.flatMap((g) =>
        g.hosts.map((h, i) => ({
          ...h,
          tier: g.tier,
          key: `${g.tier}:${h.asset_id || h.host}:${i}`,
        }))
      ),
    [groups]
  )

  const cells = useMemo(() => {
    const finding = (row: HostRow) => (
      <ServiceLinks
        row={row}
        link={(s) =>
          s.finding_id ? (
            <Link href={`/findings/${s.finding_id}`} className="hover:underline">
              {t(`findings.status.${s.finding_status}`, s.finding_status)}
            </Link>
          ) : null
        }
      />
    )
    const task = (row: HostRow) => (
      <ServiceLinks
        row={row}
        link={(s) =>
          s.task_id ? (
            <Link href={`/remediation/tasks/${s.task_id}`} className="hover:underline">
              {t('emergingThreats.assets.openTask')}
            </Link>
          ) : null
        }
      />
    )
    const criticality = (row: HostRow) =>
      row.criticality ? t(`criticality.${row.criticality}`, row.criticality) : ''
    return { finding, task, criticality }
  }, [t])

  const columns = useMemo<ColumnDef<HostRow>[]>(
    () => [
      {
        id: 'asset',
        header: t('emergingThreats.assets.asset'),
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <HostTitle row={row.original} />,
      },
      {
        id: 'exposure',
        header: t('emergingThreats.assets.exposure'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.internet_facing ? (
            <Badge variant="outline">{t('emergingThreats.assets.internetFacing')}</Badge>
          ) : (
            <Dash />
          ),
      },
      {
        id: 'criticality',
        header: t('emergingThreats.assets.criticality'),
        enableSorting: false,
        cell: ({ row }) => cells.criticality(row.original) || <Dash />,
      },
      {
        id: 'product',
        header: t('emergingThreats.assets.product'),
        enableSorting: false,
        cell: ({ row }) => row.original.products.join(', ') || <Dash />,
      },
      {
        id: 'version',
        header: t('emergingThreats.assets.version'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.versions.length > 0 ? (
            <span className="font-mono text-xs">{row.original.versions.join(', ')}</span>
          ) : (
            <Dash />
          ),
      },
      {
        id: 'finding',
        header: t('emergingThreats.assets.finding'),
        enableSorting: false,
        cell: ({ row }) => cells.finding(row.original),
      },
      {
        id: 'task',
        header: t('emergingThreats.assets.task'),
        enableSorting: false,
        cell: ({ row }) => cells.task(row.original),
      },
    ],
    [t, cells]
  )

  const rowGroups = useMemo(
    () => ({
      getKey: (r: HostRow) => r.tier,
      order: TIER_ORDER,
      getLabel: (key: string) => t(`emergingThreats.assets.${key}`, key),
      renderHeader: (key: string, groupRows: HostRow[]) => (
        <span>
          <span className="text-sm font-medium text-foreground">
            {t(`emergingThreats.assets.${key}`, key)}
          </span>{' '}
          <span className="tabular-nums">({groupRows.length})</span>
        </span>
      ),
    }),
    [t]
  )

  const mobileRow = (row: HostRow) => {
    const facts: KeyValueItem[] = []
    const criticality = cells.criticality(row)
    if (criticality)
      facts.push({
        key: 'criticality',
        label: t('emergingThreats.assets.criticality'),
        value: criticality,
      })
    if (row.products.length > 0)
      facts.push({
        key: 'product',
        label: t('emergingThreats.assets.product'),
        value: row.products.join(', '),
      })
    if (row.versions.length > 0)
      facts.push({
        key: 'version',
        label: t('emergingThreats.assets.version'),
        value: row.versions.join(', '),
        token: true,
      })
    if (row.services.some((s) => s.finding_id))
      facts.push({
        key: 'finding',
        label: t('emergingThreats.assets.finding'),
        value: cells.finding(row),
      })
    if (row.services.some((s) => s.task_id))
      facts.push({ key: 'task', label: t('emergingThreats.assets.task'), value: cells.task(row) })
    return (
      <div className="flex flex-col gap-2 px-3 py-3">
        <div className="flex items-start justify-between gap-2">
          <HostTitle row={row} />
          {row.internet_facing && (
            <Badge variant="outline" className="shrink-0">
              {t('emergingThreats.assets.internetFacing')}
            </Badge>
          )}
        </div>
        {facts.length > 0 && (
          <KeyValueList
            items={facts}
            size="meta"
            className="grid-cols-[minmax(5rem,max-content)_minmax(0,1fr)]"
          />
        )}
      </div>
    )
  }

  const noneConfirmed = !error && !groups.some((g) => g.tier !== 'possible' && g.hosts.length > 0)

  return (
    <section aria-label={t('emergingThreats.assets.title')} className="flex flex-col gap-3">
      {noneConfirmed && (
        <p className="text-sm text-muted-foreground">{t('emergingThreats.assets.noneConfirmed')}</p>
      )}
      {(rows.length > 0 || !!error) && (
        <DataTable
          error={error}
          onRetry={onRetry}
          columns={columns}
          data={rows}
          getRowId={(r) => r.key}
          showSearch={false}
          showColumnToggle={false}
          pageSize={50}
          pageSizeOptions={PAGE_SIZES}
          rowGroups={rowGroups}
          mobileRow={mobileRow}
        />
      )}
    </section>
  )
}
