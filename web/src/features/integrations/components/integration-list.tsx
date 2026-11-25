'use client'

import { useMemo, useState, type ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { EmptyState, ErrorState, MetricStrip, type MetricStripItem } from '@/features/shared'
import { TableSkeleton } from '@/components/list-page-parts'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The one list pattern of the integrations settings pages (hub, source
 * control, notification channels, event forwarding, ticketing, field and
 * import mappings), so they read alike:
 *
 * - an optional status strip with the same three tiles everywhere
 *   (Connected / Needs attention / Pending), full width, that filters the
 *   list; it is hidden while the list is empty (no row of zeros above an
 *   empty state);
 * - then the error, a table-shaped skeleton, the empty state, or the table;
 * - the table rows open their record by the name, and further actions sit in
 *   the "..." row menu (`DataTableRowActions`); a refresh is the toolbar's
 *   icon `RefreshButton`.
 *
 * The page's create button goes in its PageHeader only while the list has
 * rows: when it is empty, the empty state carries the one create button
 * (`action`), so the same button is never shown twice.
 */

export type IntegrationStatusGroup = 'connected' | 'attention' | 'pending'

/** The strip group of a connection status (the statuses every integration API returns). */
export function integrationStatusGroup(status: string | undefined): IntegrationStatusGroup | null {
  switch (status) {
    case 'connected':
      return 'connected'
    case 'error':
    case 'expired':
      return 'attention'
    case 'pending':
    case 'disconnected':
      return 'pending'
    default:
      return null
  }
}

interface IntegrationListProps<T> {
  rows: readonly T[]
  isLoading: boolean
  error?: unknown
  onRetry: () => void
  /** What failed to load, lower case ("notification channels"). */
  errorTitle: string
  /** The strip group of a row. Omit for a list without a status strip. */
  groupOf?: (row: T) => IntegrationStatusGroup | null
  empty: { icon: LucideIcon; title: string; description: string; action?: ReactNode }
  /** The table of the rows the strip lets through. */
  children: (visible: T[]) => ReactNode
}

export function IntegrationList<T>({
  rows,
  isLoading,
  error,
  onRetry,
  errorTitle,
  groupOf,
  empty,
  children,
}: IntegrationListProps<T>) {
  const { t } = useTranslation()
  const [group, setGroup] = useState<IntegrationStatusGroup | null>(null)

  const counts = useMemo(() => {
    const c: Record<IntegrationStatusGroup, number> = { connected: 0, attention: 0, pending: 0 }
    if (groupOf)
      for (const row of rows) {
        const g = groupOf(row)
        if (g) c[g] += 1
      }
    return c
  }, [rows, groupOf])

  const visible = useMemo(
    () => (group && groupOf ? rows.filter((r) => groupOf(r) === group) : [...rows]),
    [rows, group, groupOf]
  )

  if (error) return <ErrorState title={errorTitle} error={error} onRetry={onRetry} />

  const tile = (key: IntegrationStatusGroup, label: string): MetricStripItem => ({
    key,
    label,
    value: counts[key],
    ...(key === 'attention' ? { tone: 'danger' as const } : {}),
    active: group === key,
    onClick: () => setGroup(group === key ? null : key),
  })
  const strip =
    groupOf && (isLoading || rows.length > 0) ? (
      <MetricStrip
        loading={isLoading}
        items={[
          tile('connected', t('integrationsHub.metrics.connected', 'Connected')),
          tile('attention', t('integrationsHub.metrics.attention', 'Needs attention')),
          tile('pending', t('integrationsHub.metrics.pending', 'Pending')),
        ]}
      />
    ) : null

  return (
    <>
      {strip}
      {isLoading ? (
        <TableSkeleton />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={empty.icon}
          title={empty.title}
          description={empty.description}
          action={empty.action}
        />
      ) : (
        <div>{children(visible)}</div>
      )}
    </>
  )
}
