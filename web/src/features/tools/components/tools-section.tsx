'use client'

/**
 * Settings > Scanning > Tools: the tools this organization can scan with,
 * as its sensors report them (api tool-availability.md). By default it lists
 * the tools at least one sensor has; "Show full catalog" adds every catalog
 * tool. Status, sensors and versions come from the sensors' manifests; the
 * switch is the organization's own on/off per tool.
 */

import { buildCsv, downloadCsv } from '@/hooks/use-csv-export'
import Link from '@/components/link'
import { useState, useMemo, useCallback } from 'react'
import { Plus, Wrench, Search, Download } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Can, useCanMutate } from '@/lib/permissions'

import { AddToolDialog } from './add-tool-dialog'
import { ToolTable } from './tool-table'
import { ToolDetailSheet } from './tool-detail-sheet'
import { CATEGORY_OPTIONS } from '../schemas/tool-schema'
import { TOOL_STATUS_META, onAnySensor, toolDisplayName, versionsLabel } from '../lib/availability'

import {
  useToolAvailability,
  useDeleteCustomTool,
  useEnableTool,
  useDisableTool,
  invalidateToolsCache,
} from '@/lib/api/tool-hooks'
import { useAllToolCategories, getCategoryNameById } from '@/lib/api/tool-category-hooks'
import type { Tool, ToolAvailabilityItem, ToolAvailabilityStatus } from '@/lib/api/tool-types'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  EmptyState,
  ErrorState,
  MetricStrip,
  PageHeader,
  type MetricStripItem,
} from '@/features/shared'

type TypeFilter = 'all' | 'builtin' | 'custom'

/** Status filters that only make sense over the whole catalog. */
const CATALOG_STATUSES: ToolAvailabilityStatus[] = ['no_sensor', 'disabled']

export function ToolsSection() {
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [detailName, setDetailName] = useState<string | null>(null)
  const [deletingTool, setDeletingTool] = useState<Tool | null>(null)
  const [editingTool, setEditingTool] = useState<Tool | null>(null)

  // Filters and search live in the URL so a view can be shared and survives
  // a reload.
  const [categoryFilter, setCategoryFilter] = useUrlFilter('category', 'all')
  const [typeParam, setTypeFilter] = useUrlFilter('type', 'all')
  const [statusParam, setStatusFilter] = useUrlFilter('status', '')
  const [updatesParam, setUpdatesFilter] = useUrlFilter('updates', '')
  const [catalogParam, setCatalogParam] = useUrlFilter('catalog', '')
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const typeFilter: TypeFilter =
    typeParam === 'builtin' || typeParam === 'custom' ? typeParam : 'all'
  const statusFilter = (statusParam || null) as ToolAvailabilityStatus | null
  const updatesOnly = updatesParam === '1'
  const showCatalog =
    catalogParam === '1' || (statusFilter != null && CATALOG_STATUSES.includes(statusFilter))

  const { data, error, isLoading, mutate } = useToolAvailability()
  const { data: categoriesData } = useAllToolCategories()

  const categoryOptions = useMemo(() => {
    if (categoriesData?.items && categoriesData.items.length > 0) {
      return categoriesData.items.map((cat) => ({ value: cat.name, label: cat.display_name }))
    }
    return CATEGORY_OPTIONS
  }, [categoriesData])

  const items = useMemo(() => data?.items ?? [], [data])

  // Every tool narrowed by category, type and search. The metrics count it:
  // a status other than no_sensor/disabled implies a sensor has the tool, so
  // its count is the same with or without the full catalog.
  const narrowed = useMemo(() => {
    let result = items
    if (categoryFilter !== 'all') {
      result = result.filter(
        (i) => getCategoryNameById(categoriesData?.items, i.tool?.category_id) === categoryFilter
      )
    }
    if (typeFilter !== 'all') {
      result = result.filter((i) =>
        typeFilter === 'builtin' ? i.tool?.is_builtin === true : i.tool?.is_builtin !== true
      )
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      result = result.filter(
        (i) =>
          i.name.toLowerCase().includes(q) ||
          toolDisplayName(i).toLowerCase().includes(q) ||
          i.tool?.description?.toLowerCase().includes(q)
      )
    }
    return result
  }, [items, categoryFilter, typeFilter, searchQuery, categoriesData])

  const visible = useMemo(() => {
    let result = showCatalog ? narrowed : narrowed.filter(onAnySensor)
    if (statusFilter) result = result.filter((i) => i.status === statusFilter)
    if (updatesOnly) result = result.filter((i) => i.update_available)
    return result
  }, [narrowed, showCatalog, statusFilter, updatesOnly])

  const detailItem = useMemo(
    () => (detailName ? (items.find((i) => i.name === detailName) ?? null) : null),
    [items, detailName]
  )

  const { trigger: deleteCustomTool, isMutating: isDeleting } = useDeleteCustomTool(
    deletingTool?.id || ''
  )
  const { trigger: enableTool } = useEnableTool()
  const { trigger: disableTool } = useDisableTool()

  const refresh = useCallback(async () => {
    await invalidateToolsCache()
    await mutate()
  }, [mutate])

  const handleRefresh = useCallback(async () => {
    await refresh()
    toast.success('Tools refreshed')
  }, [refresh])

  const handleToggleEnabled = useCallback(
    async (item: ToolAvailabilityItem, on: boolean) => {
      if (!item.tool) return
      try {
        await (on ? enableTool(item.tool.id) : disableTool(item.tool.id))
        toast.success(`${toolDisplayName(item)} ${on ? 'enabled' : 'disabled'}`)
        await refresh()
      } catch (err) {
        toast.error(getErrorMessage(err, `Failed to ${on ? 'enable' : 'disable'} the tool`))
      }
    },
    [enableTool, disableTool, refresh]
  )

  const handleEditTool = useCallback((tool: Tool) => {
    setEditingTool(tool)
    setDetailName(null)
    setAddDialogOpen(true)
  }, [])

  const handleDeleteClick = useCallback((tool: Tool) => {
    setDeletingTool(tool)
    setDetailName(null)
    setDeleteDialogOpen(true)
  }, [])

  const handleDeleteConfirm = useCallback(async () => {
    if (!deletingTool) return
    try {
      await deleteCustomTool()
      toast.success(`Tool "${deletingTool.display_name}" deleted`)
      await refresh()
      setDeleteDialogOpen(false)
      setDeletingTool(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to delete tool'))
    }
  }, [deletingTool, deleteCustomTool, refresh])

  const handleExport = useCallback(() => {
    const csv = buildCsv(
      [
        'Name',
        'Display Name',
        'Category',
        'Status',
        'Sensors online',
        'Sensors total',
        'Versions',
        'Last reported',
        'Enabled',
      ],
      visible.map((i) => [
        i.name,
        toolDisplayName(i),
        getCategoryNameById(categoriesData?.items, i.tool?.category_id),
        TOOL_STATUS_META[i.status].label,
        String(i.sensors_online),
        String(i.sensors_total),
        versionsLabel(i),
        i.last_reported_at ?? '',
        i.enabled ? 'Yes' : 'No',
      ])
    )
    downloadCsv(csv, 'tools.csv')
    toast.success('Tools exported')
  }, [visible, categoriesData])

  const canEditTool = useCanMutate('PUT /api/v1/tools/{id}')
  const canDeleteTool = useCanMutate('DELETE /api/v1/tools/{id}')
  const canToggle = useCanMutate('PATCH /api/v1/tools/settings')

  // Each metric's count is exactly what its filter shows.
  const countOf = (st: ToolAvailabilityStatus) => narrowed.filter((i) => i.status === st).length
  const toggleStatus = (st: ToolAvailabilityStatus) => {
    setUpdatesFilter('')
    setStatusFilter(statusFilter === st ? '' : st)
  }
  const statusMetric = (
    st: ToolAvailabilityStatus,
    tone?: MetricStripItem['tone']
  ): MetricStripItem => ({
    key: st,
    label: TOOL_STATUS_META[st].label,
    value: countOf(st),
    tone,
    onClick: () => toggleStatus(st),
    active: statusFilter === st,
  })
  const metrics: MetricStripItem[] = [
    statusMetric('ready'),
    statusMetric('offline_only', 'warning'),
    statusMetric('no_sensor'),
    statusMetric('outdated', 'warning'),
    statusMetric('disabled'),
    {
      key: 'updates',
      label: 'Updates available',
      value: narrowed.filter((i) => i.update_available).length,
      onClick: () => {
        setStatusFilter('')
        setUpdatesFilter(updatesOnly ? '' : '1')
      },
      active: updatesOnly,
    },
  ]

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search tools…"
          aria-label="Search tools"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="h-9 ps-9"
        />
      </div>
      <Select value={categoryFilter} onValueChange={setCategoryFilter}>
        <SelectTrigger className="h-9 w-[150px]" aria-label="Category">
          <SelectValue placeholder="All categories" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All categories</SelectItem>
          {categoryOptions.map((cat) => (
            <SelectItem key={cat.value} value={cat.value}>
              {cat.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={typeFilter} onValueChange={setTypeFilter}>
        <SelectTrigger className="h-9 w-[130px]" aria-label="Type">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All types</SelectItem>
          <SelectItem value="builtin">Built-in</SelectItem>
          <SelectItem value="custom">Custom</SelectItem>
        </SelectContent>
      </Select>
    </>
  )

  const toolbarEnd = (
    <>
      <div className="flex items-center gap-2">
        <Switch
          id="tools-full-catalog"
          checked={showCatalog}
          disabled={statusFilter != null && CATALOG_STATUSES.includes(statusFilter)}
          onCheckedChange={(on) => setCatalogParam(on ? '1' : '')}
        />
        <Label htmlFor="tools-full-catalog" className="whitespace-nowrap text-sm font-normal">
          Show full catalog
        </Label>
      </div>
      <RefreshButton onClick={handleRefresh} loading={isLoading} />
    </>
  )

  const hasFilter =
    !!searchQuery ||
    categoryFilter !== 'all' ||
    typeFilter !== 'all' ||
    !!statusFilter ||
    updatesOnly
  const nothingOnSensors = !showCatalog && items.length > 0 && !items.some(onAnySensor)

  let body: React.ReactNode
  if (error) {
    body = <ErrorState title="tools" error={error} onRetry={handleRefresh} />
  } else if (isLoading) {
    body = <TableSkeleton rows={6} />
  } else if (nothingOnSensors && !hasFilter) {
    body = (
      <EmptyState
        icon={Wrench}
        title="No sensor has reported a tool yet"
        description="Tools show here once a sensor of this organization reports them. Install a sensor, or look at the full catalog."
        card={false}
        action={
          <div className="flex flex-wrap justify-center gap-2">
            <Button size="sm" variant="outline" onClick={() => setCatalogParam('1')}>
              Show full catalog
            </Button>
            <Button size="sm" asChild>
              <Link href="/sensors">Go to Sensors</Link>
            </Button>
          </div>
        }
      />
    )
  } else {
    body = (
      <ToolTable
        items={visible}
        categories={categoriesData?.items}
        onViewTool={(i) => setDetailName(i.name)}
        onEditTool={canEditTool ? handleEditTool : undefined}
        onDeleteTool={canDeleteTool ? handleDeleteClick : undefined}
        onToggleEnabled={canToggle ? handleToggleEnabled : undefined}
        toolbarStart={toolbarStart}
        toolbarEnd={toolbarEnd}
        emptyMessage={
          showCatalog
            ? 'No tools match these filters'
            : 'No tool on your sensors matches these filters'
        }
      />
    )
  }

  return (
    <>
      <PageHeader
        title="Tools"
        description="The tools your sensors report, and whether a scan with each can run now. Add custom tools for your own scanners."
      >
        <Button variant="outline" size="sm" onClick={handleExport}>
          <Download className="h-4 w-4" />
          Export
        </Button>
        <Can route="POST /api/v1/tools">
          <Button size="sm" onClick={() => setAddDialogOpen(true)}>
            <Plus className="h-4 w-4" />
            Add tool
          </Button>
        </Can>
      </PageHeader>

      <MetricStrip className="mt-5" loading={isLoading} items={metrics} />

      <div className="mt-5">{body}</div>

      <AddToolDialog
        open={addDialogOpen}
        onOpenChange={(open) => {
          setAddDialogOpen(open)
          if (!open) setEditingTool(null)
        }}
        onSuccess={refresh}
        tool={editingTool}
      />

      {detailItem && (
        <ToolDetailSheet
          item={detailItem}
          categories={categoriesData?.items}
          open={!!detailItem}
          onOpenChange={(open) => !open && setDetailName(null)}
          onEdit={canEditTool ? handleEditTool : undefined}
          onDelete={canDeleteTool ? handleDeleteClick : undefined}
          onToggleEnabled={canToggle ? handleToggleEnabled : undefined}
        />
      )}

      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Delete tool"
        desc={
          <>
            Are you sure you want to delete <strong>{deletingTool?.display_name}</strong>? This
            action cannot be undone.
          </>
        }
        confirmText="Delete"
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDeleteConfirm}
      />
    </>
  )
}
