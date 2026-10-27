'use client'

/**
 * Columns of the endpoint and change tables, shared by the tenant-wide Web
 * surface page and the Web section of an origin asset, so the two never drift
 * (one shared component per pattern). Every cell shows scan output as text.
 */

import { useCallback, useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { RelativeTime, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import type {
  WebEndpointEventResponse,
  WebEndpointResponse,
  WebPathCatalogEntry,
} from '@/lib/api/generated'
import { AuthPill, CatalogBadge, ExcludedBadge, MethodBadge, PathText } from './web-surface-badges'

/** Change kinds in the order the filter lists them, with their English text. */
export const EVENT_KINDS: Record<string, string> = {
  appeared: 'Appeared',
  returned: 'Seen again',
  gone: 'Gone',
  status_changed: 'Status changed',
  auth_changed: 'Auth changed',
  param_added: 'New parameter',
}

export function num(v: number | undefined): number {
  return v ?? 0
}

/** Detail of a change event in words (status codes and auth states only). */
export function eventDetail(e: WebEndpointEventResponse): string {
  const d = (e.detail ?? {}) as Record<string, unknown>
  if (e.kind === 'status_changed' || e.kind === 'auth_changed') {
    return `${String(d.from ?? '?')} → ${String(d.to ?? '?')}`
  }
  if (e.kind === 'param_added') return `${String(d.count ?? 1)} new`
  return ''
}

/** The label of a change kind in the active language. */
export function useEventLabel(): (kind: string | undefined) => string {
  const { t } = useTranslation()
  return useCallback(
    (kind) =>
      kind && EVENT_KINDS[kind]
        ? t(`attackSurface.web.event.${kind}`, EVENT_KINDS[kind])
        : (kind ?? ''),
    [t]
  )
}

export function useEndpointColumns(): ColumnDef<WebEndpointResponse>[] {
  const { t } = useTranslation()
  return useMemo<ColumnDef<WebEndpointResponse>[]>(
    () => [
      {
        id: 'endpoint',
        header: t('attackSurface.web.col.endpoint', 'Endpoint'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex min-w-0 items-start gap-2">
            <MethodBadge method={row.original.method} />
            <StackedCell
              truncate
              className="max-w-[420px]"
              primary={<PathText path={row.original.path_template} />}
              secondary={row.original.origin}
            />
          </div>
        ),
      },
      {
        id: 'status',
        header: t('attackSurface.web.col.status', 'Status'),
        enableSorting: false,
        cell: ({ row }) => <span className="tabular-nums">{row.original.last_status || '-'}</span>,
      },
      {
        id: 'auth',
        header: t('attackSurface.web.col.auth', 'Auth'),
        enableSorting: false,
        cell: ({ row }) => <AuthPill state={row.original.auth_state} />,
      },
      {
        id: 'flags',
        header: t('attackSurface.web.col.notes', 'Notes'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            <CatalogBadge entry={row.original.catalog} />
            {!row.original.in_scope && <ExcludedBadge exclusionId={row.original.exclusion_id} />}
            {row.original.state === 'ignored' && (
              <Badge variant="secondary" className="font-normal">
                {t('attackSurface.web.ignored', 'Ignored')}
              </Badge>
            )}
          </div>
        ),
      },
      {
        id: 'params',
        header: t('attackSurface.web.col.params', 'Params'),
        enableSorting: false,
        cell: ({ row }) => <span className="tabular-nums">{num(row.original.param_count)}</span>,
      },
      {
        id: 'last_seen',
        header: t('attackSurface.web.col.lastSeen', 'Last seen'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
    ],
    [t]
  )
}

export function useEventColumns(
  catalogByKey: Map<string, WebPathCatalogEntry>
): ColumnDef<WebEndpointEventResponse>[] {
  const { t } = useTranslation()
  const label = useEventLabel()
  return useMemo<ColumnDef<WebEndpointEventResponse>[]>(
    () => [
      {
        id: 'at',
        header: t('attackSurface.web.col.when', 'When'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.at} />,
      },
      {
        id: 'kind',
        header: t('attackSurface.web.col.change', 'Change'),
        enableSorting: false,
        cell: ({ row }) => (
          <Badge
            variant={row.original.kind === 'gone' ? 'outline' : 'secondary'}
            className="font-normal"
          >
            {label(row.original.kind)}
          </Badge>
        ),
      },
      {
        id: 'endpoint',
        header: t('attackSurface.web.col.endpoint', 'Endpoint'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex min-w-0 items-start gap-2">
            <MethodBadge method={row.original.method} />
            <StackedCell
              truncate
              className="max-w-[420px]"
              primary={<PathText path={row.original.path_template} />}
              secondary={row.original.origin}
            />
          </div>
        ),
      },
      {
        id: 'detail',
        header: t('attackSurface.web.col.detail', 'Detail'),
        enableSorting: false,
        cell: ({ row }) => <span className="text-sm">{eventDetail(row.original) || '-'}</span>,
      },
      {
        id: 'sensitive',
        header: t('attackSurface.web.col.sensitive', 'Sensitive'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.catalog_key ? (
            <CatalogBadge entry={catalogByKey.get(row.original.catalog_key)} />
          ) : null,
      },
    ],
    [t, label, catalogByKey]
  )
}
