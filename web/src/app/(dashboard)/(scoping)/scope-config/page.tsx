'use client'

import { useState, useMemo, useCallback, useEffect, useEffectEvent } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableRowActions,
  MetricStrip,
  type MetricStripItem,
} from '@/features/shared'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useDebounce } from '@/hooks/use-debounce'
import { useUrlFilter, useUrlFilterNumber } from '@/hooks/use-url-param'
import { cn } from '@/lib/utils'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger, TabsCount } from '@/components/ui/tabs'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertTriangle,
  Ban,
  Loader2,
  Pencil,
  Plus,
  Search as SearchIcon,
  Trash2,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  type ScopeTargetType,
  getScopeTypeConfig,
  useScopeTargetsApi,
  useScopeExclusionsApi,
  useScopeStatsApi,
  useScopeSettingsApi,
  useCreateScopeExclusionApi,
  useUpdateScopeExclusionApi,
  useDeleteScopeExclusionApi,
  invalidateScopeCache,
  invalidateScopeExclusionsCache,
  invalidateScopeStatsCache,
  ScopeEntryDialog,
  ScopeTargetTypeSelect,
  SCOPE_TARGET_TYPE_ICON,
  scopeTargetTypeLabel,
  type ApiScopeExclusion,
} from '@/features/scope'
import {
  ScopeTargetsPanel,
  SCOPE_PAGE_SIZES as PAGE_SIZES,
} from '@/features/scope/components/scope-targets-panel'
import { post } from '@/lib/api/client'
import { EASMSeedsPanel } from '@/features/attack-surface/components/easm-seeds'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import { getErrorMessage } from '@/lib/api/error-handler'

// Use shared validation from scope feature types
const validatePattern = (
  type: ScopeTargetType,
  pattern: string
): { valid: boolean; error?: string } => {
  if (!pattern.trim()) {
    return { valid: false, error: 'Pattern is required' }
  }

  const config = getScopeTypeConfig(type)
  if (!config) {
    return { valid: true } // Allow if no config (generic type)
  }

  if (!config.validation.pattern.test(pattern)) {
    return { valid: false, error: config.validation.message }
  }

  // Additional IP validation
  if (type === 'ip_range' || type === 'ip_address') {
    const ipPart = pattern.split('/')[0]
    const octets = ipPart.split('.').map(Number)
    if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) {
      return { valid: false, error: 'IP octets must be between 0-255' }
    }
    if (pattern.includes('/')) {
      const cidr = parseInt(pattern.split('/')[1])
      if (isNaN(cidr) || cidr < 0 || cidr > 32) {
        return { valid: false, error: 'CIDR must be between 0-32' }
      }
    }
  }

  return { valid: true }
}

// Targets | Exclusions. The old Overview tab charted the whole inventory and the
// Schedules tab never ran (nothing executes scope schedules; Scans owns
// scheduling), so an old `?tab=overview` or `?tab=schedules` link lands on Targets.
const SCOPE_TABS = ['targets', 'exclusions', 'seeds'] as const
type ScopeTab = (typeof SCOPE_TABS)[number]

export default function ScopeConfigPage() {
  // Permission check for write operations
  const canWriteScope = useHasPermission(Permission.ScopeWrite)
  // Scope approvers add effective entries and approve requests (RFC-054 §6.1).
  const canApproveScope = useHasPermission(Permission.ScopeApprove)
  // A new exclusion is pending until someone else holding this approves it.
  const canApproveExclusions = useHasPermission(Permission.ScopeExclusionsApprove)

  // Tab, search, type filter and page live in the URL so a view can be linked
  // to. One set of list params serves whichever table tab is open (they are
  // cleared on tab change), and each API call only receives them for its own tab
  // so the other tabs' counts stay unfiltered.
  const [tabParam, setTabParam] = useUrlFilter('tab', 'targets')
  const tab: ScopeTab = (SCOPE_TABS as readonly string[]).includes(tabParam)
    ? (tabParam as ScopeTab)
    : 'targets'
  const [searchParam, setSearchParam] = useUrlFilter('q', '')
  const [typeFilter, setTypeFilter] = useUrlFilter('type', 'all')
  const [statusFilter, setStatusFilter] = useUrlFilter('status', 'all')
  const [page, setPage] = useUrlFilterNumber('page', 1)
  const [perPageParam, setPerPage] = useUrlFilterNumber('per_page', 20)
  const perPage = PAGE_SIZES.includes(perPageParam) ? perPageParam : 20
  const [searchValue, setSearchValue] = useState(searchParam)
  const debouncedSearch = useDebounce(searchValue, 300)
  // Only the debounced input triggers a URL write. The URL value is read as an
  // effect event (latest value, not a dependency), so a URL change such as Back
  // does not write the stale debounced text over it.
  const commitSearch = useEffectEvent((next: string) => {
    if (next !== searchParam) {
      setSearchParam(next)
      setPage(1)
    }
  })
  useEffect(() => {
    commitSearch(debouncedSearch)
  }, [debouncedSearch])

  // Seeds belong to the Attack surface module (RFC-036 §6.3).
  const { moduleIds } = useTenantModules()
  const seedsTabVisible = moduleIds.includes('attack_surface')

  const selectTab = (next: string) => {
    if (next === tab) return
    setSearchValue('')
    setSearchParam('')
    setTypeFilter('all')
    setStatusFilter('all')
    setPage(1)
    setTabParam(next)
  }
  const setTypeFilterAndReset = (v: string) => {
    setTypeFilter(v)
    setPage(1)
  }
  const setStatusFilterAndReset = (v: string) => {
    setStatusFilter(v)
    setPage(1)
  }
  const showPending = () => {
    if (tab !== 'targets') selectTab('targets')
    setStatusFilter('pending')
    setPage(1)
  }
  const listParams = (forTab: ScopeTab) =>
    tab === forTab
      ? { search: searchParam || undefined, type: typeFilter !== 'all' ? typeFilter : undefined }
      : { search: undefined, type: undefined }
  const exclusionParams = listParams('exclusions')

  // Validation error state
  const [validationError, setValidationError] = useState<string | null>(null)

  // Dialog states
  const [isAddTargetOpen, setIsAddTargetOpen] = useState(false)
  const [isAddExclusionOpen, setIsAddExclusionOpen] = useState(false)
  const [editExclusion, setEditExclusion] = useState<ApiScopeExclusion | null>(null)
  const [deleteExclusion, setDeleteExclusion] = useState<ApiScopeExclusion | null>(null)

  // Form states
  const [exclusionForm, setExclusionForm] = useState({
    type: 'domain' as ScopeTargetType,
    pattern: '',
    reason: '',
  })

  // API hooks for fetching data (using debounced search values)
  const { data: targetsData, isLoading: targetsLoading } = useScopeTargetsApi({ per_page: 1 })
  // Entries waiting for approval, for the approvers' banner and the metric.
  const { data: pendingData } = useScopeTargetsApi({ status: 'pending', per_page: 1 })
  const pendingCount = pendingData?.total ?? 0
  const { data: scopeSettings } = useScopeSettingsApi()
  const membersMayRequest = scopeSettings?.one_off_targets === 'admins_and_requests'

  const { data: exclusionsData, isLoading: exclusionsLoading } = useScopeExclusionsApi({
    search: exclusionParams.search,
    exclusion_type: exclusionParams.type,
    page: tab === 'exclusions' ? page : 1,
    per_page: tab === 'exclusions' ? perPage : 20,
  })

  const { data: statsData, isLoading: statsLoading } = useScopeStatsApi()

  // Mutation hooks
  const { trigger: createExclusion, isMutating: isCreatingExclusion } = useCreateScopeExclusionApi()
  const { trigger: updateExclusion, isMutating: isUpdatingExclusion } = useUpdateScopeExclusionApi(
    editExclusion?.id || ''
  )
  const { trigger: removeExclusion, isMutating: isRemovingExclusion } = useDeleteScopeExclusionApi(
    deleteExclusion?.id || ''
  )

  // Extracted data - memoized for stable references
  const exclusions = useMemo(() => exclusionsData?.data || [], [exclusionsData?.data])

  // Stats (with fallback to 0 for undefined values)
  const stats = useMemo(() => {
    if (statsData) {
      return {
        targets: statsData.total_targets ?? 0,
        activeTargets: statsData.active_targets ?? 0,
        exclusions: statsData.total_exclusions ?? 0,
        // Share of discovered assets an active target covers (and no
        // exclusion removes), computed by the API; not a share of targets.
        coverage: Math.round(statsData.coverage ?? 0),
      }
    }
    // Fallback when stats API hasn't loaded yet.
    //
    // Use API totals (targetsData?.total etc) instead of array .length so the
    // numbers don't drop to "current page count" while statsData is loading.
    // Active/enabled counts are still derived from the loaded page because we
    // don't have a per-status breakdown without statsData; this is a brief
    // loading-state fallback only — once statsData arrives the branch above
    // takes over with authoritative numbers.
    return {
      targets: targetsData?.total ?? 0,
      activeTargets: 0,
      exclusions: exclusionsData?.total ?? 0,
      // Only the API knows how much of the inventory the targets cover.
      coverage: 0,
    }
  }, [statsData, targetsData, exclusionsData])

  const checkDuplicateExclusion = useCallback(
    (pattern: string, excludeId?: string): boolean => {
      return exclusions.some((e) => e.pattern === pattern && e.id !== excludeId)
    },
    [exclusions]
  )

  // Toggle exclusion status using activate/deactivate endpoints
  const toggleExclusionStatus = async (exclusion: ApiScopeExclusion) => {
    try {
      const action = exclusion.status === 'active' ? 'deactivate' : 'activate'
      await post<ApiScopeExclusion>(`/api/v1/scope/exclusions/${exclusion.id}/${action}`)
      await invalidateScopeExclusionsCache()
      await invalidateScopeStatsCache()
      toast.success(`Exclusion ${action}d successfully`)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to update exclusion status'))
    }
  }

  // Approve or reject a pending exclusion. The API refuses (403) when the
  // reviewer is the requester.
  const reviewExclusion = async (exclusion: ApiScopeExclusion, action: 'approve' | 'reject') => {
    try {
      await post<ApiScopeExclusion>(`/api/v1/scope/exclusions/${exclusion.id}/${action}`)
      await invalidateScopeExclusionsCache()
      await invalidateScopeCache()
      toast.success(action === 'approve' ? 'Exclusion approved' : 'Exclusion rejected')
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to ${action} exclusion`))
    }
  }

  // Exclusion handlers
  const resetExclusionForm = () => {
    setExclusionForm({ type: 'domain', pattern: '', reason: '' })
    setValidationError(null)
  }

  const handleAddExclusion = async () => {
    // Validate pattern format
    const validation = validatePattern(exclusionForm.type, exclusionForm.pattern)
    if (!validation.valid) {
      setValidationError(validation.error || 'Invalid pattern')
      return
    }

    // Check for duplicates
    if (checkDuplicateExclusion(exclusionForm.pattern)) {
      setValidationError('This pattern already exists in exclusions')
      return
    }

    try {
      await createExclusion({
        exclusion_type: exclusionForm.type,
        pattern: exclusionForm.pattern,
        reason: exclusionForm.reason,
      })
      await invalidateScopeCache()
      toast.success('Exclusion submitted for approval')
      setIsAddExclusionOpen(false)
      resetExclusionForm()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to add exclusion'))
    }
  }

  const handleEditExclusion = async () => {
    if (!editExclusion) return

    // Validate pattern format
    const validation = validatePattern(exclusionForm.type, exclusionForm.pattern)
    if (!validation.valid) {
      setValidationError(validation.error || 'Invalid pattern')
      return
    }

    // Check for duplicates (exclude current exclusion)
    if (checkDuplicateExclusion(exclusionForm.pattern, editExclusion.id)) {
      setValidationError('This pattern already exists in exclusions')
      return
    }

    try {
      await updateExclusion({
        reason: exclusionForm.reason,
      })
      await invalidateScopeCache()
      toast.success('Exclusion updated successfully')
      setEditExclusion(null)
      resetExclusionForm()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to update exclusion'))
    }
  }

  const handleDeleteExclusion = async () => {
    if (!deleteExclusion) return
    try {
      await removeExclusion()
      await invalidateScopeCache()
      toast.success('Exclusion removed successfully')
      setDeleteExclusion(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to remove exclusion'))
    }
  }

  const openEditExclusion = (exclusion: ApiScopeExclusion) => {
    setExclusionForm({
      type: (exclusion.exclusion_type ?? '') as ScopeTargetType,
      pattern: exclusion.pattern ?? '',
      reason: exclusion.reason ?? '',
    })
    setEditExclusion(exclusion)
  }

  // Get pattern placeholder and help text from shared config
  const getTypeConfig = (type: ScopeTargetType) => {
    const config = getScopeTypeConfig(type)
    return {
      placeholder: config?.placeholder || 'Enter pattern',
      helpText: config?.helpText || '',
    }
  }

  const exclusionFormFields = (
    <div className="space-y-4">
      {validationError && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4" />
          {validationError}
        </div>
      )}
      <div className="space-y-2">
        <Label>Type</Label>
        <ScopeTargetTypeSelect
          value={exclusionForm.type}
          disabled={!!editExclusion}
          onValueChange={(v) => {
            setExclusionForm({ ...exclusionForm, type: v as ScopeTargetType })
            setValidationError(null)
          }}
        />
      </div>
      <div className="space-y-2">
        <Label>Pattern *</Label>
        <Input
          placeholder={getTypeConfig(exclusionForm.type).placeholder}
          value={exclusionForm.pattern}
          disabled={!!editExclusion}
          onChange={(e) => {
            setExclusionForm({ ...exclusionForm, pattern: e.target.value })
            setValidationError(null)
          }}
        />
        <p className="text-muted-foreground text-xs">
          {editExclusion
            ? 'Type and pattern identify the exclusion and cannot be changed after creation. Remove and re-add to change them.'
            : 'Pattern to exclude from security assessments'}
        </p>
      </div>
      <div className="space-y-2">
        <Label>Reason</Label>
        <Input
          placeholder="Reason for exclusion"
          value={exclusionForm.reason}
          onChange={(e) => setExclusionForm({ ...exclusionForm, reason: e.target.value })}
        />
      </div>
    </div>
  )

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search exclusions…"
          aria-label={`Search ${tab}`}
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          className="h-9 ps-9"
        />
      </div>
      <ScopeTargetTypeSelect
        value={typeFilter}
        onValueChange={setTypeFilterAndReset}
        withAll
        className="h-9 w-auto min-w-36"
        aria-label="Filter by type"
      />
    </>
  )

  const onTablePagination = (p: { pageIndex: number; pageSize: number }) => {
    if (p.pageSize !== perPage) {
      setPerPage(p.pageSize)
      setPage(1)
    } else {
      setPage(p.pageIndex + 1)
    }
  }

  const filtersActive = !!searchParam || typeFilter !== 'all'

  const exclusionColumns: ColumnDef<ApiScopeExclusion>[] = [
    {
      accessorKey: 'pattern',
      header: 'Pattern',
      enableHiding: false,
      cell: ({ row }) => (
        <code className="rounded bg-muted px-2 py-1 text-sm">{row.original.pattern}</code>
      ),
    },
    {
      accessorKey: 'exclusion_type',
      header: 'Type',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {SCOPE_TARGET_TYPE_ICON[row.original.exclusion_type ?? ''] || <Ban className="h-4 w-4" />}
          <span className="text-sm text-foreground">
            {scopeTargetTypeLabel(row.original.exclusion_type ?? '')}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'reason',
      header: 'Reason',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{row.original.reason}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const exclusion = row.original
        if (exclusion.status === 'pending') {
          return (
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Pending approval</span>
              {canApproveExclusions && (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 text-xs"
                    onClick={() => reviewExclusion(exclusion, 'approve')}
                  >
                    Approve
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 px-2 text-xs"
                    onClick={() => reviewExclusion(exclusion, 'reject')}
                  >
                    Reject
                  </Button>
                </>
              )}
            </div>
          )
        }
        if (exclusion.status === 'rejected') {
          return <span className="text-xs text-muted-foreground">Rejected</span>
        }
        return (
          <div className="flex items-center gap-2">
            <Switch
              checked={exclusion.status === 'active'}
              onCheckedChange={() => toggleExclusionStatus(exclusion)}
              // Switching off an exclusion in effect takes the approval
              // permission (and someone other than the requester): the API
              // refuses scope:write alone.
              disabled={!canWriteScope || (exclusion.status === 'active' && !canApproveExclusions)}
              aria-label={`Toggle ${exclusion.pattern}`}
            />
            <span
              className={cn('text-xs', exclusion.status !== 'active' && 'text-muted-foreground')}
            >
              {exclusion.status === 'active' ? 'Excluded' : 'Inactive'}
            </span>
          </div>
        )
      },
    },
    {
      accessorKey: 'created_by',
      header: 'Created by',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{row.original.created_by}</span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => (
        <Can permission={[Permission.ScopeWrite, Permission.ScopeDelete]}>
          <DataTableRowActions
            actions={[
              {
                label: 'Edit',
                icon: Pencil,
                onClick: () => openEditExclusion(row.original),
                permission: Permission.ScopeWrite,
              },
              {
                label: 'Remove',
                icon: Trash2,
                onClick: () => setDeleteExclusion(row.original),
                destructive: true,
                permission: Permission.ScopeDelete,
              },
            ]}
          />
        </Can>
      ),
    },
  ]

  const tableSkeleton = (
    <div className="space-y-2 rounded-xl border p-3">
      {[1, 2, 3, 4].map((i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  )

  const metrics: MetricStripItem[] = [
    {
      key: 'targets',
      label: 'Scope entries',
      value: stats.targets,
      hint: `${stats.activeTargets} active`,
      onClick: () => {
        selectTab('targets')
      },
    },
    {
      key: 'pending',
      label: 'Pending approval',
      value: pendingCount,
      tone: pendingCount > 0 ? 'warning' : 'default',
      hint: pendingCount > 0 ? 'authorize nothing until approved' : undefined,
      onClick: showPending,
      active: tab === 'targets' && statusFilter === 'pending',
    },
    {
      key: 'exclusions',
      label: 'Exclusions',
      value: stats.exclusions,
      onClick: () => selectTab('exclusions'),
    },
    {
      key: 'coverage',
      label: 'Inventory in scope',
      value: `${stats.coverage}%`,
      hint: 'of discovered assets match an active entry',
    },
  ]

  // Approvers add entries; anyone else with scope:write requests a one-off
  // when the organization accepts requests (RFC-054 §6.1).
  const addButton =
    tab === 'seeds' ? null : tab === 'exclusions' ? (
      <Button size="sm" onClick={() => setIsAddExclusionOpen(true)}>
        <Plus className="me-2 h-4 w-4" />
        Add exclusion
      </Button>
    ) : canApproveScope ? (
      <Button size="sm" onClick={() => setIsAddTargetOpen(true)}>
        <Plus className="me-2 h-4 w-4" />
        Add to scope
      </Button>
    ) : membersMayRequest ? (
      <Button size="sm" onClick={() => setIsAddTargetOpen(true)}>
        <Plus className="me-2 h-4 w-4" />
        Request access
      </Button>
    ) : null

  return (
    <>
      <Main>
        <PageHeader
          title="Boundaries"
          description="What your organization may probe, and what scans must never touch. *.example.com covers example.com and every name below it; exclusions win over every entry."
        >
          <Can permission={Permission.ScopeWrite}>{addButton}</Can>
        </PageHeader>

        <MetricStrip className="mt-5" loading={statsLoading} items={metrics} />

        {canApproveScope &&
          pendingCount > 0 &&
          !(tab === 'targets' && statusFilter === 'pending') && (
            <Alert className="mt-5">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
                <span>
                  {pendingCount} scope {pendingCount === 1 ? 'entry waits' : 'entries wait'} for
                  approval. They authorize nothing until approved.
                </span>
                <Button size="sm" variant="outline" onClick={showPending}>
                  Review
                </Button>
              </AlertDescription>
            </Alert>
          )}

        <Tabs value={tab} onValueChange={selectTab} className="mt-5">
          <div className="no-scrollbar -mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
            <TabsList>
              <TabsTrigger value="targets">
                Targets <TabsCount value={targetsLoading ? '…' : (targetsData?.total ?? 0)} />
              </TabsTrigger>
              <TabsTrigger value="exclusions">
                Exclusions{' '}
                <TabsCount
                  value={exclusionsLoading ? '…' : (exclusionsData?.total ?? exclusions.length)}
                />
              </TabsTrigger>
              {seedsTabVisible && <TabsTrigger value="seeds">Seeds</TabsTrigger>}
            </TabsList>
          </div>

          <TabsContent value="targets" className="mt-5">
            <ScopeTargetsPanel
              query={{
                search: tab === 'targets' ? searchParam : '',
                type: tab === 'targets' ? typeFilter : 'all',
                status: tab === 'targets' ? statusFilter : 'all',
                page: tab === 'targets' ? page : 1,
                perPage,
              }}
              searchInput={searchValue}
              onSearchInput={setSearchValue}
              onTypeChange={setTypeFilterAndReset}
              onStatusChange={setStatusFilterAndReset}
              onPagination={onTablePagination}
            />
          </TabsContent>

          <TabsContent value="exclusions" className="mt-5">
            {exclusionsLoading && !exclusionsData ? (
              tableSkeleton
            ) : (
              <DataTable
                columns={exclusionColumns}
                data={exclusions}
                showSearch={false}
                toolbarStart={toolbarStart}
                manualPagination
                rowCount={exclusionsData?.total ?? 0}
                pagination={{ pageIndex: page - 1, pageSize: perPage }}
                onPaginationChange={onTablePagination}
                pageSizeOptions={PAGE_SIZES}
                emptyMessage={
                  filtersActive ? 'No exclusions match' : 'No exclusions configured yet'
                }
                emptyDescription={
                  filtersActive
                    ? 'Try adjusting your search or type filter.'
                    : 'Add an exclusion to keep something out of scans.'
                }
              />
            )}
          </TabsContent>

          {seedsTabVisible && (
            <TabsContent value="seeds" className="mt-5">
              <EASMSeedsPanel />
            </TabsContent>
          )}
        </Tabs>
      </Main>

      <ScopeEntryDialog open={isAddTargetOpen} onOpenChange={setIsAddTargetOpen} />

      {/* Add Exclusion Dialog */}
      <Dialog
        open={isAddExclusionOpen}
        onOpenChange={(open) => {
          setIsAddExclusionOpen(open)
          if (!open) {
            resetExclusionForm()
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add exclusion</DialogTitle>
            <DialogDescription>Add a pattern to exclude from scope</DialogDescription>
          </DialogHeader>
          {exclusionFormFields}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsAddExclusionOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleAddExclusion} disabled={isCreatingExclusion}>
              {isCreatingExclusion && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              Add Exclusion
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Exclusion Dialog */}
      <Dialog
        open={!!editExclusion}
        onOpenChange={(open) => {
          if (!open) {
            setEditExclusion(null)
            resetExclusionForm()
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit exclusion</DialogTitle>
            <DialogDescription>Update exclusion information</DialogDescription>
          </DialogHeader>
          {exclusionFormFields}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditExclusion(null)}>
              Cancel
            </Button>
            <Button onClick={handleEditExclusion} disabled={isUpdatingExclusion}>
              {isUpdatingExclusion && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Exclusion Dialog */}
      <ConfirmDialog
        open={!!deleteExclusion}
        onOpenChange={(open) => !open && setDeleteExclusion(null)}
        title="Remove exclusion?"
        desc={<>Remove &quot;{deleteExclusion?.pattern}&quot; from exclusions?</>}
        confirmText="Remove"
        destructive
        isLoading={isRemovingExclusion}
        handleConfirm={handleDeleteExclusion}
      />
    </>
  )
}
