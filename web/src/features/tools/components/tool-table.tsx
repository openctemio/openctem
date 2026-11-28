'use client'

import type * as React from 'react'
import { useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import Image from 'next/image'
import { ArrowUpCircle, ExternalLink, Eye, Github, Settings, Trash2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  type RowAction,
  type DataTableSearch,
} from '@/features/shared'
import type { Tool, ToolAvailabilityItem } from '@/lib/api/tool-types'
import type { ToolCategory } from '@/lib/api/tool-category-types'
import { getCategoryNameById, getCategoryDisplayNameById } from '@/lib/api/tool-category-hooks'
import { formatRelative } from '@/lib/format-date'
import { safeImageSrc } from '@/lib/safe-href'
import { sanitizeExternalUrl } from '@/lib/utils'

import { TOOL_AVAILABILITY_STATUSES, toolDisplayName, versionsLabel } from '../lib/availability'
import { ToolCategoryIcon } from './tool-category-icon'
import { ToolSensorsCell, ToolStatusBadge, ToolTrustBadge } from './tool-availability'

interface ToolTableProps {
  items: ToolAvailabilityItem[]
  categories?: ToolCategory[] // For looking up category name from category_id
  onViewTool: (item: ToolAvailabilityItem) => void
  onEditTool?: (tool: Tool) => void
  onDeleteTool?: (tool: Tool) => void
  /** Switch the tool on or off for the organization; omitted without permission. */
  onToggleEnabled?: (item: ToolAvailabilityItem, enabled: boolean) => void
  /** Passed through to the DataTable toolbar (search, filters). */
  search?: DataTableSearch
  toolbarStart?: React.ReactNode
  toolbarEnd?: React.ReactNode
  emptyMessage?: string
}

// SECURITY: tool github_url / docs_url are tenant-authored and the API's URL
// validator accepts opaque schemes such as `javascript:`. Route through the
// shared sanitizer (same guard every other window.open site uses) so a stored
// `javascript:`/`data:` URL cannot execute when another user clicks the action.
const openExternal = (url: string) =>
  window.open(sanitizeExternalUrl(url), '_blank', 'noopener,noreferrer')

const STATUS_ORDER = new Map(TOOL_AVAILABILITY_STATUSES.map((s, i) => [s, i]))

// Frame widths (px) under which a column gives way, so the table fits its
// frame instead of cutting a header: the last report, the version, the
// category, then the sensor count (all are in the tool's details).
const TOOL_HIDE_BELOW = { lastReported: 1040, versions: 870, category: 720, sensors: 600 } as const

export function ToolTable({
  items,
  categories,
  onViewTool,
  onEditTool,
  onDeleteTool,
  onToggleEnabled,
  search,
  toolbarStart,
  toolbarEnd,
  emptyMessage,
}: ToolTableProps) {
  const { t } = useTranslation()
  const categoryName = useCallback(
    (item: ToolAvailabilityItem) => getCategoryNameById(categories, item.tool?.category_id),
    [categories]
  )
  const categoryDisplayName = useCallback(
    (item: ToolAvailabilityItem) =>
      item.tool ? getCategoryDisplayNameById(categories, item.tool.category_id) : '',
    [categories]
  )

  const columns = useMemo<ColumnDef<ToolAvailabilityItem>[]>(
    () => [
      {
        id: 'name',
        meta: { kind: 'name', label: t('scans.tools.col.tool', 'Tool') },
        accessorFn: (i) => `${toolDisplayName(i)} ${i.name} ${i.tool?.description ?? ''}`,
        sortingFn: (a, b) => toolDisplayName(a.original).localeCompare(toolDisplayName(b.original)),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.tools.col.tool', 'Tool')} />
        ),
        cell: ({ row }) => {
          const item = row.original
          const logoSrc = safeImageSrc(item.tool?.logo_url)
          return (
            <div className="flex min-w-0 items-center gap-3">
              {logoSrc ? (
                // unoptimized: the logo URL is tenant/remote data; it must not be
                // fetched through the Next image optimizer (no remotePatterns).
                <Image
                  src={logoSrc}
                  alt=""
                  width={28}
                  height={28}
                  unoptimized
                  className="h-7 w-7 shrink-0 rounded-md object-contain"
                />
              ) : (
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-muted">
                  <ToolCategoryIcon
                    category={categoryName(item)}
                    className="h-4 w-4 text-muted-foreground"
                  />
                </div>
              )}
              <div className="min-w-0">
                <p className="flex items-center gap-1.5 truncate font-medium">
                  <span className="truncate">{toolDisplayName(item)}</span>
                  {item.tool && !item.tool.is_builtin && (
                    <Badge variant="outline" className="text-[10px] font-normal">
                      {t('scans.tools.badge.custom', 'Custom')}
                    </Badge>
                  )}
                  {!item.in_catalog && (
                    <Badge variant="outline" className="text-[10px] font-normal">
                      {t('scans.tools.badge.notInCatalog', 'Not in catalog')}
                    </Badge>
                  )}
                </p>
                <p className="truncate font-mono text-xs text-muted-foreground">{item.name}</p>
              </div>
            </div>
          )
        },
      },
      {
        id: 'category',
        meta: {
          kind: 'text',
          width: 150,
          hideBelow: TOOL_HIDE_BELOW.category,
          label: t('scans.tools.col.category', 'Category'),
        },
        accessorFn: (i) => categoryDisplayName(i),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.tools.col.category', 'Category')}
          />
        ),
        cell: ({ row }) =>
          row.original.tool ? (
            <Badge variant="outline" className="gap-1">
              <ToolCategoryIcon category={categoryName(row.original)} className="h-3 w-3" />
              {categoryDisplayName(row.original)}
            </Badge>
          ) : (
            <span className="text-xs text-muted-foreground">–</span>
          ),
      },
      {
        id: 'status',
        meta: { kind: 'text', width: 150, label: t('scans.tools.col.status', 'Status') },
        accessorFn: (i) => STATUS_ORDER.get(i.status) ?? 99,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.tools.col.status', 'Status')} />
        ),
        cell: ({ row }) => (
          <span className="inline-flex flex-wrap items-center gap-1">
            <ToolStatusBadge item={row.original} />
            <ToolTrustBadge item={row.original} />
          </span>
        ),
      },
      {
        id: 'sensors',
        meta: {
          kind: 'number',
          hideBelow: TOOL_HIDE_BELOW.sensors,
          label: t('scans.tools.col.sensors', 'Sensors'),
        },
        accessorFn: (i) => i.sensors_online * 1000 + i.sensors_total,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.tools.col.sensors', 'Sensors')} />
        ),
        cell: ({ row }) => <ToolSensorsCell item={row.original} />,
      },
      {
        id: 'versions',
        meta: {
          kind: 'text',
          width: 120,
          hideBelow: TOOL_HIDE_BELOW.versions,
          label: t('scans.tools.col.versions', 'Versions'),
        },
        accessorFn: (i) => versionsLabel(i),
        enableSorting: false,
        header: t('scans.tools.col.versions', 'Versions'),
        cell: ({ row }) => {
          const item = row.original
          const label = versionsLabel(item)
          return (
            <div className="flex items-center gap-2">
              <span className="text-xs tabular-nums">{label || '–'}</span>
              {item.update_available && item.latest_version && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Badge variant="secondary" className="gap-1 tabular-nums">
                      <ArrowUpCircle className="h-3 w-3" />
                      {item.latest_version}
                    </Badge>
                  </TooltipTrigger>
                  <TooltipContent>
                    {t(
                      'scans.tools.update.tooltip',
                      'A sensor runs an older version than {version}, the newest known',
                      { version: item.latest_version }
                    )}
                  </TooltipContent>
                </Tooltip>
              )}
            </div>
          )
        },
      },
      {
        id: 'last_reported',
        meta: {
          kind: 'datetime-recent',
          hideBelow: TOOL_HIDE_BELOW.lastReported,
          label: t('scans.tools.col.lastReported', 'Last reported'),
        },
        accessorFn: (i) => i.last_reported_at ?? '',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.tools.col.lastReported', 'Last reported')}
          />
        ),
        cell: ({ row }) => (
          <span
            className="text-xs text-muted-foreground"
            title={row.original.last_reported_at ?? undefined}
          >
            {formatRelative(row.original.last_reported_at, '–')}
          </span>
        ),
      },
      {
        id: 'enabled',
        meta: { kind: 'status', width: 96, label: t('scans.tools.col.enabled', 'Enabled') },
        accessorFn: (i) => (i.enabled ? 1 : 0),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.tools.col.enabled', 'Enabled')} />
        ),
        cell: ({ row }) => {
          const item = row.original
          // A tool outside the catalog, or one the platform switched off,
          // has no organization switch.
          const switchable = !!onToggleEnabled && !!item.tool && item.tool.is_active
          return (
            <span onClick={(e) => e.stopPropagation()} className="inline-flex">
              <Switch
                checked={item.enabled}
                disabled={!switchable}
                aria-label={
                  item.enabled
                    ? t('scans.tools.switch.disable', 'Disable {name}', {
                        name: toolDisplayName(item),
                      })
                    : t('scans.tools.switch.enable', 'Enable {name}', {
                        name: toolDisplayName(item),
                      })
                }
                onCheckedChange={(on) => onToggleEnabled?.(item, on)}
              />
            </span>
          )
        },
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const item = row.original
          const tool = item.tool
          const actions: RowAction[] = [
            {
              label: t('scans.tools.action.viewDetails', 'View details'),
              icon: Eye,
              onClick: () => onViewTool(item),
            },
          ]
          if (tool && !tool.is_builtin && onEditTool) {
            actions.push({
              label: t('scans.tools.action.edit', 'Edit'),
              icon: Settings,
              onClick: () => onEditTool(tool),
            })
          }
          if (tool?.github_url) {
            const url = tool.github_url
            // i18n-ok: brand name
            actions.push({ label: 'GitHub', icon: Github, onClick: () => openExternal(url) })
          }
          if (tool?.docs_url) {
            const url = tool.docs_url
            actions.push({
              label: t('scans.tools.action.docs', 'Documentation'),
              icon: ExternalLink,
              onClick: () => openExternal(url),
            })
          }
          if (tool && !tool.is_builtin && onDeleteTool) {
            actions.push({
              label: t('scans.tools.action.delete', 'Delete'),
              icon: Trash2,
              onClick: () => onDeleteTool(tool),
              destructive: true,
              separatorBefore: true,
            })
          }
          return <DataTableRowActions title={tool?.name} actions={actions} />
        },
      },
    ],
    [onViewTool, onEditTool, onDeleteTool, onToggleEnabled, categoryName, categoryDisplayName, t]
  )

  return (
    <DataTable
      columns={columns}
      data={items}
      getRowId={(i) => i.name}
      showSearch={false}
      onRowClick={onViewTool}
      search={search}
      toolbarStart={toolbarStart}
      toolbarEnd={toolbarEnd}
      pinActions
      emptyMessage={emptyMessage ?? t('scans.tools.empty.filters', 'No tools match these filters')}
    />
  )
}
