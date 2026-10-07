'use client'

import { useState, useMemo, useCallback, useEffect, useEffectEvent } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  ActorChip,
  TonePill,
  type RowAction,
  PageHeader,
  DataTable,
  DataTableRowActions,
  MetricStrip,
  type MetricStripItem,
} from '@/features/shared'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useDebounce } from '@/hooks/use-debounce'
import { useUrlFilter, useUrlFilterNumber } from '@/hooks/use-url-param'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
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
  Plus,
  Pencil,
  Trash2,
  Ban,
  Search as SearchIcon,
  AlertTriangle,
  Loader2,
  Power,
  PowerOff,
  Check,
  X,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  type ScopeTargetType,
  getScopeTypeConfig,
  // API hooks
  useScopeTargetsApi,
  useScopeExclusionsApi,
  useScopeStatsApi,
  useUpdateScopeTargetApi,
  useDeleteScopeTargetApi,
  useCreateScopeExclusionApi,
  useUpdateScopeExclusionApi,
  useDeleteScopeExclusionApi,
  invalidateScopeCache,
  invalidateScopeTargetsCache,
  invalidateScopeExclusionsCache,
  invalidateScopeStatsCache,
  ScopeEntryDialog,
  ScopeTargetTypeSelect,
  EXCLUSION_KINDS,
  scopeKindIcon,
  scopeKindOf,
  scopeTargetTypeLabel,
  storedTypesFor,
  coversText,
  canApproveEntry,
  approveScopeTarget,
  rejectScopeTarget,
  entryStatus,
  expiryText,
  SCOPE_ENTRY_STATUS_HINT,
  SCOPE_ENTRY_STATUS_LABEL,
  SCOPE_ENTRY_STATUS_TONE,
  scopeErrorMessage,
  // API types
  type ApiScopeTarget,
  type ApiScopeExclusion,
} from '@/features/scope'
import { post } from '@/lib/api/client'
import { EASMDomainProofPanel } from '@/features/attack-surface/components/easm-domain-proof'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'

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
const SCOPE_TABS = ['targets', 'exclusions', 'proof'] as const
type ScopeTab = (typeof SCOPE_TABS)[number]
const PAGE_SIZES = [10, 20, 30, 50, 100]

export default function ScopeConfigPage() {
  // Permission check for write operations
  const canApproveScope = useHasPermission(Permission.ScopeApprove)
  const { t } = useTranslation()
  // The profile API, not the auth store: the store is empty after a reload.
  const user = useDisplayUser()
  // Entries waiting for approval (RFC-054 §6.1): approvers see the count
  // and approve or reject from the row menu.
  const { data: pendingData } = useScopeTargetsApi({ status: 'pending', per_page: 1 })
  const pendingCount = pendingData?.total ?? 0
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

  // Domain proof belongs to the Attack surface module (RFC-036 §6.3).
  const { moduleIds } = useTenantModules()
  const proofTabVisible = moduleIds.includes('attack_surface')

  const selectTab = (next: string) => {
    if (next === tab) return
    setSearchValue('')
    setSearchParam('')
    setTypeFilter('all')
    setPage(1)
    setTabParam(next)
  }
  const setTypeFilterAndReset = (v: string) => {
    setTypeFilter(v)
    setPage(1)
  }
  const kindFilter = scopeKindOf(typeFilter)
  const listParams = (forTab: ScopeTab) =>
    tab === forTab
      ? {
          search: searchParam || undefined,
          type: kindFilter ? storedTypesFor(kindFilter) : undefined,
        }
      : { search: undefined, type: undefined }
  const targetParams = listParams('targets')
  const exclusionParams = listParams('exclusions')

  // Validation error state
  const [validationError, setValidationError] = useState<string | null>(null)

  // Dialog states
  const [isAddTargetOpen, setIsAddTargetOpen] = useState(false)
  const [isAddExclusionOpen, setIsAddExclusionOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<ApiScopeTarget | null>(null)
  const [editExclusion, setEditExclusion] = useState<ApiScopeExclusion | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ApiScopeTarget | null>(null)
  const [deleteExclusion, setDeleteExclusion] = useState<ApiScopeExclusion | null>(null)

  // Form states
  const [targetForm, setTargetForm] = useState({
    type: 'domain' as ScopeTargetType,
    pattern: '',
    description: '',
    priority: 0,
    tags: [] as string[],
  })

  const [exclusionForm, setExclusionForm] = useState({
    type: 'domain' as ScopeTargetType,
    pattern: '',
    reason: '',
  })

  // API hooks for fetching data (using debounced search values)
  const { data: targetsData, isLoading: targetsLoading } = useScopeTargetsApi({
    search: targetParams.search,
    target_type: targetParams.type,
    page: tab === 'targets' ? page : 1,
    per_page: tab === 'targets' ? perPage : 20,
  })

  const { data: exclusionsData, isLoading: exclusionsLoading } = useScopeExclusionsApi({
    search: exclusionParams.search,
    exclusion_type: exclusionParams.type,
    page: tab === 'exclusions' ? page : 1,
    per_page: tab === 'exclusions' ? perPage : 20,
  })

  const { data: statsData, isLoading: statsLoading } = useScopeStatsApi()

  // Mutation hooks
  const { trigger: updateTarget, isMutating: isUpdatingTarget } = useUpdateScopeTargetApi(
    editTarget?.id || ''
  )
  const { trigger: removeTarget, isMutating: isRemovingTarget } = useDeleteScopeTargetApi(
    deleteTarget?.id || ''
  )

  const { trigger: createExclusion, isMutating: isCreatingExclusion } = useCreateScopeExclusionApi()
  const { trigger: updateExclusion, isMutating: isUpdatingExclusion } = useUpdateScopeExclusionApi(
    editExclusion?.id || ''
  )
  const { trigger: removeExclusion, isMutating: isRemovingExclusion } = useDeleteScopeExclusionApi(
    deleteExclusion?.id || ''
  )

  // Extracted data - memoized for stable references
  const targets = useMemo(() => targetsData?.data || [], [targetsData?.data])
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
      activeTargets: targets.filter((t) => t.status === 'active').length,
      exclusions: exclusionsData?.total ?? 0,
      // Only the API knows how much of the inventory the targets cover.
      coverage: 0,
    }
  }, [statsData, targetsData, exclusionsData, targets])

  // Duplicate check helpers
  const checkDuplicateTarget = useCallback(
    (pattern: string, excludeId?: string): boolean => {
      return targets.some((t) => t.pattern === pattern && t.id !== excludeId)
    },
    [targets]
  )

  const checkDuplicateExclusion = useCallback(
    (pattern: string, excludeId?: string): boolean => {
      return exclusions.some((e) => e.pattern === pattern && e.id !== excludeId)
    },
    [exclusions]
  )

  const decideTarget = async (target: ApiScopeTarget, approve: boolean) => {
    try {
      const id = target.id ?? ''
      const updated = approve ? await approveScopeTarget(id) : await rejectScopeTarget(id)
      await invalidateScopeTargetsCache()
      await invalidateScopeStatsCache()
      toast.success(
        !approve
          ? `${target.pattern} rejected`
          : updated?.status === 'active'
            ? `${target.pattern} is in scope`
            : `Approval recorded; ${target.pattern} still waits for another approver`
      )
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'The decision was not saved'))
    }
  }

  const setTargetActive = async (target: ApiScopeTarget, active: boolean) => {
    try {
      const updated = await post<ApiScopeTarget>(
        `/api/v1/scope/targets/${target.id}/${active ? 'activate' : 'deactivate'}`
      )
      await invalidateScopeTargetsCache()
      await invalidateScopeStatsCache()
      toast.success(
        !active
          ? `${target.pattern} deactivated`
          : updated?.status === 'pending'
            ? `${target.pattern} is waiting for approval`
            : `${target.pattern} activated`
      )
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'Failed to update the entry'))
    }
  }

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

  // Target handlers
  const resetTargetForm = () => {
    setTargetForm({ type: 'domain', pattern: '', description: '', priority: 0, tags: [] })
    setValidationError(null)
  }

  const handleEditTarget = async () => {
    if (!editTarget) return

    // Validate pattern format
    const validation = validatePattern(targetForm.type, targetForm.pattern)
    if (!validation.valid) {
      setValidationError(validation.error || 'Invalid pattern')
      return
    }

    // Check for duplicates (exclude current target)
    if (checkDuplicateTarget(targetForm.pattern, editTarget.id)) {
      setValidationError('This pattern already exists in targets')
      return
    }

    try {
      await updateTarget({
        description: targetForm.description,
        priority: targetForm.priority,
        tags: targetForm.tags,
      })
      await invalidateScopeCache()
      toast.success('Target updated successfully')
      setEditTarget(null)
      resetTargetForm()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to update target'))
    }
  }

  const handleDeleteTarget = async () => {
    if (!deleteTarget) return
    try {
      await removeTarget()
      await invalidateScopeCache()
      toast.success('Target removed successfully')
      setDeleteTarget(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to remove target'))
    }
  }

  const openEditTarget = (target: ApiScopeTarget) => {
    setTargetForm({
      type: (target.target_type ?? '') as ScopeTargetType,
      pattern: target.pattern ?? '',
      description: target.description ?? '',
      priority: target.priority ?? 0,
      tags: target.tags ?? [],
    })
    setEditTarget(target)
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

  // Form JSX
  const targetFormFields = (
    <div className="space-y-4">
      {validationError && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4" />
          {validationError}
        </div>
      )}
      <div className="space-y-2">
        <Label>Kind</Label>
        <ScopeTargetTypeSelect
          value={targetForm.type}
          disabled={!!editTarget}
          onValueChange={(v) => {
            setTargetForm({ ...targetForm, type: v as ScopeTargetType })
            setValidationError(null)
          }}
        />
      </div>
      <div className="space-y-2">
        <Label>Pattern *</Label>
        <Input
          placeholder={getTypeConfig(targetForm.type).placeholder}
          value={targetForm.pattern}
          disabled={!!editTarget}
          onChange={(e) => {
            setTargetForm({ ...targetForm, pattern: e.target.value })
            setValidationError(null)
          }}
        />
        <p className="text-muted-foreground text-xs">
          {editTarget
            ? 'Type and pattern identify the target and cannot be changed after creation. Remove and re-add to change them.'
            : getTypeConfig(targetForm.type).helpText}
        </p>
      </div>
      <div className="space-y-2">
        <Label>Description</Label>
        <Input
          placeholder="Description of this target"
          value={targetForm.description}
          onChange={(e) => setTargetForm({ ...targetForm, description: e.target.value })}
        />
      </div>
    </div>
  )

  const exclusionFormFields = (
    <div className="space-y-4">
      {validationError && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4" />
          {validationError}
        </div>
      )}
      <div className="space-y-2">
        <Label>Kind</Label>
        <ScopeTargetTypeSelect
          value={exclusionForm.type}
          disabled={!!editExclusion}
          only={EXCLUSION_KINDS}
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

  const typeFilterSelect = (
    <ScopeTargetTypeSelect
      value={kindFilter ?? 'all'}
      onValueChange={setTypeFilterAndReset}
      withAll
      only={tab === 'exclusions' ? EXCLUSION_KINDS : undefined}
      className="h-9 w-auto min-w-36"
      aria-label="Filter by kind"
    />
  )

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder={tab === 'targets' ? 'Search targets…' : 'Search exclusions…'}
          aria-label={`Search ${tab}`}
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          className="h-9 ps-9"
        />
      </div>
      {typeFilterSelect}
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

  // No inline toggles (research/53 SC5): activating widens scope and may wait
  // for approval, so it is a labelled menu action that says so; deactivating
  // narrows and applies at once.
  const targetActions = (e: ApiScopeTarget): RowAction[] => {
    const st = entryStatus(e)
    const out: RowAction[] = [
      {
        label: 'Edit',
        icon: Pencil,
        onClick: () => openEditTarget(e),
        permission: Permission.ScopeWrite,
      },
    ]
    if (st === 'pending' && canApproveScope) {
      // The requester, or someone who already approved, cannot approve: the
      // item stays visible with the reason instead of failing with a 403.
      const mayDecide = canApproveEntry(e, user?.id)
      const why =
        e.created_by === user?.id
          ? 'You requested this; another approver must approve it.'
          : 'You already approved this; it waits for another approver.'
      out.push(
        {
          label: 'Approve',
          icon: Check,
          onClick: () => void decideTarget(e, true),
          disabled: !mayDecide,
          disabledReason: why,
        },
        {
          label: 'Reject',
          icon: X,
          onClick: () => void decideTarget(e, false),
          disabled: e.created_by === user?.id,
          disabledReason: 'You requested this; another approver decides.',
        }
      )
    }
    if (st === 'active') {
      out.push({
        label: 'Deactivate',
        icon: PowerOff,
        onClick: () => void setTargetActive(e, false),
        permission: Permission.ScopeWrite,
      })
    } else if (st === 'inactive') {
      out.push({
        label: 'Activate (may need approval)',
        icon: Power,
        onClick: () => void setTargetActive(e, true),
        disabled: !canApproveScope,
        disabledReason: 'Activating widens scope: only a scope approver can do it.',
      })
    }
    out.push({
      label: 'Remove',
      icon: Trash2,
      onClick: () => setDeleteTarget(e),
      destructive: true,
      separatorBefore: true,
      permission: Permission.ScopeDelete,
    })
    return out
  }

  const exclusionActions = (x: ApiScopeExclusion): RowAction[] => {
    const out: RowAction[] = [
      {
        label: 'Edit',
        icon: Pencil,
        onClick: () => openEditExclusion(x),
        permission: Permission.ScopeWrite,
      },
    ]
    if (x.status === 'active') {
      // Lifting an exclusion widens scope: approvers only (the API checks).
      out.push({
        label: 'Deactivate (scans may reach it)',
        icon: PowerOff,
        onClick: () => void toggleExclusionStatus(x),
        disabled: !canApproveExclusions,
        disabledReason:
          'Lifting an exclusion widens scope: it needs the exclusion approve permission.',
      })
    } else if (x.status === 'inactive') {
      out.push({
        label: 'Activate',
        icon: Power,
        onClick: () => void toggleExclusionStatus(x),
        permission: Permission.ScopeWrite,
      })
    }
    out.push({
      label: 'Remove',
      icon: Trash2,
      onClick: () => setDeleteExclusion(x),
      destructive: true,
      separatorBefore: true,
      permission: Permission.ScopeDelete,
    })
    return out
  }

  const targetColumns: ColumnDef<ApiScopeTarget>[] = [
    {
      accessorKey: 'pattern',
      header: 'Pattern',
      enableHiding: false,
      cell: ({ row }) => (
        <div className="min-w-0 space-y-0.5">
          <code className="break-all rounded bg-muted px-1.5 py-0.5 text-sm">
            {row.original.pattern}
          </code>
          <p className="text-xs text-muted-foreground">Covers {coversText(row.original)}</p>
        </div>
      ),
    },
    {
      accessorKey: 'target_type',
      header: 'Kind',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {scopeKindIcon(row.original.target_type)}
          <span className="text-sm text-foreground">
            {scopeTargetTypeLabel(row.original.target_type ?? '')}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'description',
      header: 'Description',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{row.original.description}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const e = row.original
        const st = entryStatus(e)
        const detail =
          st === 'pending'
            ? `${e.approvals?.length ?? 0} of ${e.approvals_required ?? 0} approvals`
            : e.expires_at && (st === 'active' || st === 'expired')
              ? expiryText(e.expires_at)
              : undefined
        return (
          <TonePill
            tone={SCOPE_ENTRY_STATUS_TONE[st]}
            label={SCOPE_ENTRY_STATUS_LABEL[st]}
            title={SCOPE_ENTRY_STATUS_HINT[st]}
            detail={detail}
            state={st}
          />
        )
      },
    },
    {
      accessorKey: 'created_by',
      header: 'Added by',
      cell: ({ row }) => <ActorChip actor={row.original.created_by} at={row.original.created_at} />,
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => (
        <Can permission={[Permission.ScopeWrite, Permission.ScopeDelete]}>
          <DataTableRowActions
            label={`Actions for ${row.original.pattern}`}
            actions={targetActions(row.original)}
          />
        </Can>
      ),
    },
  ]

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
      header: 'Kind',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-muted-foreground">
          {scopeKindIcon(row.original.exclusion_type) || <Ban className="h-4 w-4" />}
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
              <TonePill tone="warning" label="Pending approval" state="pending" />
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
          return <TonePill tone="destructive" label="Rejected" state="rejected" />
        }
        return exclusion.status === 'active' ? (
          <TonePill
            tone="success"
            label="Excluded"
            detail={exclusion.expires_at ? expiryText(exclusion.expires_at) : undefined}
            state="active"
          />
        ) : (
          <TonePill tone="muted" label="Inactive" state="inactive" />
        )
      },
    },
    {
      accessorKey: 'created_by',
      header: 'Added by',
      cell: ({ row }) => <ActorChip actor={row.original.created_by} at={row.original.created_at} />,
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => (
        <Can permission={[Permission.ScopeWrite, Permission.ScopeDelete]}>
          <DataTableRowActions
            label={`Actions for ${row.original.pattern}`}
            actions={exclusionActions(row.original)}
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
      label: 'In-scope targets',
      value: stats.targets,
      hint: `${stats.activeTargets} active`,
      onClick: () => selectTab('targets'),
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
      hint: 'of the internet-facing inventory you can see is covered by an active target',
    },
  ]

  const addButton =
    tab === 'proof' ? null : tab === 'exclusions' ? (
      <Button size="sm" onClick={() => setIsAddExclusionOpen(true)}>
        <Plus className="me-2 h-4 w-4" />
        Add exclusion
      </Button>
    ) : (
      <Button size="sm" onClick={() => setIsAddTargetOpen(true)}>
        <Plus className="me-2 h-4 w-4" />
        {canApproveScope ? 'Add to scope' : 'Request access'}
      </Button>
    )

  return (
    <>
      <Main>
        <PageHeader
          title="Scope"
          description="What scans may touch. Anything not listed is out of scope, and an exclusion always wins."
        >
          <Can permission={Permission.ScopeWrite}>{addButton}</Can>
        </PageHeader>

        <MetricStrip className="mt-5" loading={statsLoading} items={metrics} />

        {canApproveScope && pendingCount > 0 && (
          <Alert className="mt-5">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              {pendingCount} scope {pendingCount === 1 ? 'entry waits' : 'entries wait'} for
              approval. They authorize nothing until approved; approve or reject them from the row
              menu.
            </AlertDescription>
          </Alert>
        )}

        <Tabs value={tab} onValueChange={selectTab} className="mt-5">
          <div className="no-scrollbar -mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
            <TabsList>
              <TabsTrigger value="targets">
                Targets{' '}
                <TabsCount value={targetsLoading ? '…' : (targetsData?.total ?? targets.length)} />
              </TabsTrigger>
              <TabsTrigger value="exclusions">
                Exclusions{' '}
                <TabsCount
                  value={exclusionsLoading ? '…' : (exclusionsData?.total ?? exclusions.length)}
                />
              </TabsTrigger>
              {proofTabVisible && <TabsTrigger value="proof">Domain proof</TabsTrigger>}
            </TabsList>
          </div>

          <TabsContent value="targets" className="mt-5">
            {targetsLoading && !targetsData ? (
              tableSkeleton
            ) : (
              <DataTable
                columns={targetColumns}
                data={targets}
                showSearch={false}
                toolbarStart={toolbarStart}
                manualPagination
                rowCount={targetsData?.total ?? 0}
                pagination={{ pageIndex: page - 1, pageSize: perPage }}
                onPaginationChange={onTablePagination}
                pageSizeOptions={PAGE_SIZES}
                emptyMessage={filtersActive ? 'No targets match' : 'No targets configured yet'}
                emptyDescription={
                  filtersActive
                    ? 'Try adjusting your search or type filter.'
                    : 'Add a target to bring it into scope.'
                }
              />
            )}
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

          {proofTabVisible && (
            <TabsContent value="proof" className="mt-5">
              <EASMDomainProofPanel />
            </TabsContent>
          )}
        </Tabs>
      </Main>

      {/* Add to scope, or request a one-off (members): RFC-054 §6.1 */}
      <ScopeEntryDialog open={isAddTargetOpen} onOpenChange={setIsAddTargetOpen} />

      {/* Edit Target Dialog */}
      <Dialog
        open={!!editTarget}
        onOpenChange={(open) => {
          if (!open) {
            setEditTarget(null)
            resetTargetForm()
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit target</DialogTitle>
            <DialogDescription>Update target information</DialogDescription>
          </DialogHeader>
          {targetFormFields}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>
              Cancel
            </Button>
            <Button onClick={handleEditTarget} disabled={isUpdatingTarget}>
              {isUpdatingTarget && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Target Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Remove target?"
        desc={<>Remove &quot;{deleteTarget?.pattern}&quot; from scope?</>}
        confirmText="Remove"
        destructive
        isLoading={isRemovingTarget}
        handleConfirm={handleDeleteTarget}
      />

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
