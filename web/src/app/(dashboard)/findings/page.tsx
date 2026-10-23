'use client'

import { evaluateFindingTransitions } from '@/features/findings/api/use-finding-transitions'
import { summarizeDryRun } from '@/features/findings/lib/transition-reasons'
import { FindingSubStatus } from '@/features/findings/components/lifecycle/finding-sub-status'
import { useListParams } from '@/hooks/use-list-params'
import {
  summarizeBulkResult,
  type BulkFindingResult,
  type BulkSummary,
} from '@/features/findings/lib/bulk-result'
import { formatEpssScore } from '@/lib/epss'
import { useState, useMemo, useCallback, useEffect, type ReactNode } from 'react'
import Link from '@/components/link'
import {
  DEFAULT_FINDING_LENS,
  lensLabelKey,
  parseFindingLens,
} from '@/features/findings/lib/state-lens'
import { mapDataFlow } from '@/features/findings/lib/finding-detail'
import {
  readFindingHash,
  useDrawerKeyboardNav,
  writeFindingHash,
} from '@/features/findings/hooks/use-drawer-navigation'
import {
  useUrlParams,
  useUrlParam,
  useUrlFilter,
  useUrlFilterList,
  useUrlSettled,
  pushUrlSearch,
  replaceUrlSearch,
} from '@/hooks/use-url-param'
import {
  buildDrillDownSearch,
  buildGroupedSearch,
  drillOrigin,
  drillValue,
  removeFilterParam,
} from '@/features/findings/lib/drilldown'
import {
  useFindingSourcesApi,
  groupFindingSourcesByCategory,
} from '@/features/config/api/finding-source-api'
import { useDebounce } from '@/hooks/use-debounce'
import { toDisplayText } from '@/lib/untrusted-text'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  SeverityBadge,
  DataTable,
  DataTableColumnHeader,
  FacetPanel,
  FacetSection,
  FacetOption,
  FacetToggle,
  FacetGroupLabel,
  BulkActionBar,
  FilterPanelToggle,
  FilterSheet,
  TruncatedText,
  DrillDownBreadcrumb,
  ErrorState,
  type MobileRowSelection,
} from '@/features/shared'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { ACTIONABLE_SEVERITIES, SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { accessStateOf, errorDetails } from '@/lib/api/access-state'
import { describePermissionDenied } from '@/lib/api/permission-denied'
import {
  useFindingQuickViews,
  refreshFindingQuickViews,
} from '@/features/findings/api/use-quick-views'
import {
  QUICK_VIEW_LABELS,
  knownQuickViews,
  quickViewIsActive,
  quickViewLabelKey,
  type QuickViewKey,
} from '@/features/findings/lib/quick-views'
import {
  FilterBar,
  InvalidFilterNotice,
  invalidFilterParams,
} from '@/features/findings/filters/filter-bar'
import {
  CONTEXT_FILTER_PARAMS,
  OWNED_FILTER_PARAMS,
  useFindingFilterContract,
  withOwnedFields,
} from '@/features/findings/filters/contract'
import { NON_FILTER_PARAMS, readFilters } from '@/features/findings/filters/model'
import { useSavedViews } from '@/features/saved-views/api/use-saved-views'
import { findingsEmptyKind } from '@/features/findings/lib/empty-kind'
import { downloadFindingsExport, exportTruncated } from '@/features/findings/api/export-findings'
import { FindingsEmptyState } from '@/features/findings/components/findings-empty-state'
import {
  Download,
  RefreshCw,
  MoreHorizontal,
  UserPlus,
  Flag,
  ExternalLink,
  Plus,
  FileUp,
  Loader2,
  Route,
  ClipboardList,
  AlertOctagon,
  Wrench,
  Search,
  ArrowLeft,
  Layers,
  SquareCode,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  FindingStatusBadge,
  FindingDetailDrawer,
  CreateFindingDialog,
  FINDING_STATUS_CONFIG,
  findingStatusesInCategory,
} from '@/features/findings'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { BranchOnlyBadge } from '@/features/findings/components/branch-only-badge'
import { SlaStatusBadge } from '@/features/sla/components/sla-status-badge'
import { SLA_STATUS_LABELS, type SLAStatus } from '@/features/repositories/types/repository.types'
import { formatDueRelative } from '@/features/sla/lib/sla'
import {
  FindingRowMenu,
  type FindingRowAction,
} from '@/features/findings/components/finding-row-menu'
import { FindingPhoneCard } from '@/features/findings/components/finding-phone-card'
import { AssigneeSelect } from '@/features/findings/components/assignee-select'
import {
  FindingGroupsTable,
  GROUP_BY_DIMENSIONS,
} from '@/features/findings/components/finding-groups-table'
import { AutoAssignDialog } from '@/features/findings/components/auto-assign-dialog'
import type { GroupByDimension } from '@/features/findings/api/use-finding-groups'
import {
  FindingContextChips,
  hasFindingContextFilters,
} from '@/features/findings/components/finding-context-chips'
import { MarkFixedDialog } from '@/features/findings/components/mark-fixed-dialog'
import { CreateTicketDialog } from '@/features/findings/components/create-ticket-dialog'
import { useCanCreateTicket } from '@/features/findings/hooks/use-can-create-ticket'
import { AddFindingsToTaskDialog } from '@/features/remediation-hub/components/add-findings-to-task-dialog'
import { CreateTaskFromQueryDialog } from '@/features/remediation-hub/components/create-task-from-query-dialog'
import { taskQueryApi } from '@/features/remediation-hub/api/use-task-query'
import { VerifyGroupActions } from '@/features/findings/components/verify-group-actions'
import { type FindingGroup } from '@/features/findings/api/use-finding-groups'
import {
  useFindingsApi,
  buildFindingsEndpoint,
  useFindingApi,
  useFindingStatsApi,
  buildFindingsExportUrl,
  type FindingStatsFilters,
} from '@/features/findings/api/use-findings-api'
import { ConfirmDialog } from '@/components/confirm-dialog'
import type { ApiFinding, FindingApiFilters } from '@/features/findings/api/finding-api.types'
import type { Finding, FindingStatus } from '@/features/findings'
import type { Severity } from '@/features/shared/types'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { del, post } from '@/lib/api/client'
import { usePermissions } from '@/context/permission-provider'
import { ImportResultsDialog } from '@/features/findings/components/import-results-dialog'
import { Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { findingAssetType } from '@/features/findings/lib/finding-asset-type'
import { findingLocation } from '@/features/findings/lib/finding-location'
import { FINDINGS_LEGACY_URL_ALIASES, migrateLegacyParams } from '@/lib/filters/url-codec'
import { SavedViewsMenu } from '@/features/saved-views/components/saved-views-menu'
import { savedViewId, type SavedView } from '@/features/saved-views/api/use-saved-views'
import { FINDINGS_LIST_HIDDEN_STATUSES } from '@/features/findings/lib/list-defaults'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

// ============================================
// Transform API Finding to UI Finding
// ============================================

/**
 * Columns hidden until the user turns them on in View: the scanner already
 * shows under the title, and the first-seen date is in the detail. Without
 * them, location, status and SLA fit at 1280px instead of scrolling away.
 */
const DEFAULT_HIDDEN_COLUMNS = { source: false, createdAt: false }

function transformApiToUiFinding(api: ApiFinding): Finding {
  // Build location string — different sources have different location semantics:
  // Scanner findings: file_path[:line] with optional branch prefix
  // Pentest findings: asset name or affected targets (no file_path)
  let locationName = ''
  if (api.file_path) {
    locationName = api.file_path
    if (api.first_detected_branch) {
      locationName = `${api.first_detected_branch}:${locationName}`
    }
    if (api.start_line) {
      locationName = `${locationName}:${api.start_line}`
    }
  } else if (api.asset?.name) {
    locationName = api.asset.name
  } else if (api.metadata?.affected_assets) {
    const targets = api.metadata.affected_assets as string[]
    locationName = targets.length > 0 ? targets[0] : ''
    if (targets.length > 1) locationName += ` +${targets.length - 1}`
  }
  if (!locationName) locationName = api.asset_id || '-'

  return {
    id: api.id,
    location: findingLocation(api),
    title: api.title || api.rule_name || api.message,
    description: api.description || api.snippet || api.message,
    severity: api.severity as Severity,
    status: api.status as FindingStatus,
    subStatusId: api.sub_status_id,
    cvss: api.cvss_score,
    cvssVector: api.cvss_vector,
    cve: api.cve_id,
    cwe: api.cwe_ids?.[0],
    owasp: api.owasp_ids?.[0],
    tags: api.tags || [],
    assets: [
      {
        id: api.asset_id,
        type: findingAssetType(api),
        name: locationName,
        url: api.location,
      },
    ],
    evidence: api.snippet
      ? [
          {
            id: 'snippet-1',
            type: 'code' as const,
            title: 'Code Snippet',
            content: api.snippet,
            createdAt: api.created_at,
            createdBy: { id: 'system', name: 'System', email: '', role: 'admin' as const },
          },
        ]
      : [],
    remediation: {
      description: api.recommendation || api.resolution || '',
      steps: [],
      references: (api.metadata?.references as string[]) || [],
      progress: api.status === 'resolved' ? 100 : 0,
    },
    // Assignee - only show name/email if enriched data is available
    // If assigned_to_user is not present, name will be empty
    // AssigneeSelect will detect this and fetch user info when needed
    assignee: api.assigned_to
      ? {
          id: api.assigned_to,
          name: api.assigned_to_user?.name || '',
          email: api.assigned_to_user?.email || '',
          role: 'analyst' as const,
        }
      : undefined,
    team: undefined,
    // Location / repo / tool — needed so the detail drawer's "Affected Code"
    // panel and code highlighter render when opened from the list. The drawer
    // reads these typed fields directly; without them they were always blank
    // even though the API returns file_path/start_line/etc. (mirrors the
    // [id] detail-page transform).
    filePath: api.file_path,
    startLine: api.start_line,
    endLine: api.end_line,
    startColumn: api.start_column,
    endColumn: api.end_column,
    repositoryUrl: api.asset?.web_url,
    branch: api.last_seen_branch || api.first_detected_branch,
    commitSha: api.last_seen_commit || api.first_detected_commit,
    ruleId: api.rule_id,
    ruleName: api.rule_name,
    toolName: api.tool_name,
    toolVersion: api.tool_version,
    contextSnippet: api.context_snippet,
    source: api.source as Finding['source'],
    scanner: api.tool_name,
    scanId: api.scan_id,
    duplicateOf: undefined,
    relatedFindings: [],
    remediationTaskId: undefined,
    discoveredAt: api.first_detected_at || api.created_at,
    resolvedAt: api.resolved_at,
    verifiedAt: undefined,
    createdAt: api.created_at,
    updatedAt: api.updated_at,
    // SLA tracking
    slaStatus: api.sla_status,
    slaDeadline: api.sla_deadline,
    // Threat Intel Enrichment (RFC-004)
    epssScore: api.epss_score,
    epssPercentile: api.epss_percentile,
    isInKev: api.is_in_kev,
    kevDueDate: api.kev_due_date,
    // Priority Classification (RFC-004)
    priorityClass: api.priority_class,
    priorityClassReason: api.priority_class_reason,
    priorityClassOverride: api.priority_class_override,
    isReachable: api.is_reachable,
    reachableFromCount: api.reachable_from_count,
    // Data Flow (Attack Path / Taint Tracking)
    // Use has_data_flow flag for list view (no full data loaded)
    // When api.data_flow is present (detail view), use full data
    hasDataFlow: api.has_data_flow || false,
    branchOnly: api.branch_only || false,
    dataFlow: mapDataFlow(api.data_flow),
  }
}

// ============================================
// Loading Skeleton
// ============================================

type FacetSeverity = SeverityLevel
const PAGE_SIZES = [10, 20, 30, 50, 100]
/** Short option labels — the trigger's layers icon already says "group by". */
const GROUP_BY_LABELS: Record<GroupByDimension, string> = {
  cve_id: 'CVE',
  rule_id: 'Rule',
  asset_id: 'Asset',
  owner_id: 'Owner',
  severity: 'Severity',
  source: 'Source',
  component_id: 'Component',
  finding_type: 'Type',
  family: 'Family',
}
const GROUP_BY_LABEL_KEYS: Record<GroupByDimension, string> = {
  cve_id: 'findings.groupBy.cve_id',
  rule_id: 'findings.groupBy.rule_id',
  asset_id: 'findings.groupBy.asset_id',
  owner_id: 'findings.groupBy.owner_id',
  severity: 'findings.groupBy.severity',
  source: 'findings.groupBy.source',
  component_id: 'findings.groupBy.component_id',
  finding_type: 'findings.groupBy.finding_type',
  family: 'findings.groupBy.family',
}
const FILTERS_OPEN_KEY = 'openctem:findings-filters-open'
/** Saved per browser: hide informational findings when no severity is picked. */
const HIDE_INFO_KEY = 'openctem:findings-hide-info'
// The status filter groups the one registry by category; every status appears
// once. Pentest pre-publication states get their own group (hidden by default).
const PRE_PUBLICATION: readonly string[] = FINDINGS_LIST_HIDDEN_STATUSES
const STATUS_GROUPS = [
  {
    key: 'open',
    label: 'Open',
    values: findingStatusesInCategory('open').filter((s) => !PRE_PUBLICATION.includes(s)),
  },
  { key: 'in_progress', label: 'In progress', values: findingStatusesInCategory('in_progress') },
  { key: 'closed', label: 'Closed', values: findingStatusesInCategory('closed') },
  { key: 'pre_publication', label: 'Pentest workflow', values: [...PRE_PUBLICATION] },
]
const SLA_OPTIONS: SLAStatus[] = ['overdue', 'exceeded', 'warning', 'on_track', 'not_applicable']
const PRIORITY_OPTIONS = [
  { value: 'P0', hint: 'Act now' },
  { value: 'P1', hint: 'High' },
  { value: 'P2', hint: 'Medium' },
  { value: 'P3', hint: 'Low' },
]

/**
 * First-load placeholder shaped like the toolbar + table it stands in for. The
 * context chips render in it already (they come from the URL, not the fetch),
 * in the same row under the toolbar as the loaded table puts them, so nothing
 * moves when the rows arrive.
 */
function FindingsTableSkeleton({ contextChips }: { contextChips?: ReactNode }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Skeleton className="h-9 min-w-0 flex-1" />
        <Skeleton className="h-9 w-28 shrink-0" />
      </div>
      {contextChips ? (
        <div
          data-testid="data-table-toolbar-below"
          className="-mt-2 flex min-w-0 flex-wrap items-center gap-2"
        >
          {contextChips}
        </div>
      ) : null}
      <div className="space-y-2 rounded-md border p-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    </div>
  )
}

/**
 * Table columns the API can sort by (FindingAllowedSortFields), keyed by column
 * id. Title, location and SLA have no server sort field, so those headers are
 * plain text rather than a control that reorders only the rows on screen.
 * `invert`: the API ranks critical / P0 first on *ascending* order, while the
 * table's "descending" means most important first.
 */
const SORTABLE_COLUMNS: Record<string, { api: string; invert?: boolean }> = {
  severity: { api: 'severity', invert: true },
  priorityClass: { api: 'priority_class', invert: true },
  source: { api: 'source' },
  status: { api: 'status' },
  createdAt: { api: 'created_at' },
  // Due date: soonest (most overdue) first on ascending.
  slaStatus: { api: 'sla_deadline' },
}

/** The URL's API sort (`-created_at`, `severity,-created_at`) → table sorting state. */
function parseSortParam(value: string): SortingState {
  const first = value.split(',')[0]?.trim()
  if (!first) return []
  const descending = first.startsWith('-')
  const key = first.replace(/^[-+]/, '')
  const entry = Object.entries(SORTABLE_COLUMNS).find(([, col]) => col.api === key)
  if (!entry) return []
  const [id, col] = entry
  // invert: the API ranks critical / P0 first ascending; the table calls that descending.
  return [{ id, desc: col.invert ? !descending : descending }]
}

/** Table sorting → API `sort` (newest first as the tie-breaker). */
function toApiSort(sorting: SortingState): string | undefined {
  const first = sorting[0]
  const col = first ? SORTABLE_COLUMNS[first.id] : undefined
  if (!first || !col) return undefined
  const ascending = col.invert ? first.desc : !first.desc
  const primary = `${ascending ? '' : '-'}${col.api}`
  return col.api === 'created_at' ? primary : `${primary},-created_at`
}

export default function FindingsPage() {
  return <FindingsContent />
}

function FindingsContent() {
  const searchParams = useUrlParams()
  // False for the one render a client-side navigation makes before the address
  // bar holds this page's URL: every URL param read then is the previous
  // page's. No request is sent until it is true (see useUrlSettled).
  const urlSettled = useUrlSettled()
  // The page URL uses the API's own filter params (RFC-048), so a page link and
  // the API query are the same words. Old page links are rewritten once below.
  const assetIdFilter = searchParams.get('asset_id')
  const scanIdFilter = searchParams.get('scan_id')

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  // Selected finding IDs, lifted from the DataTable via onSelectionChange. The
  // table owns its checkbox state internally; previously nothing synced it out
  // so selectedCount was always 0 and the bulk-action bar never appeared.
  const [selectedFindings, setSelectedFindings] = useState<Finding[]>([])
  const selectedFindingIds = useMemo(() => selectedFindings.map((f) => f.id), [selectedFindings])
  // Bumped to clear the table's own checkbox state along with ours.
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setSelectedFindings([])
    setSelectionEpoch((e) => e + 1)
  }, [])
  // Filters live in the URL so a view can be linked to. "The criticals from our
  // VA scanner" should be a link someone can paste, not a sequence of clicks to
  // reproduce.
  // Severity / status / priority are multi-select lists (comma-separated). A
  // legacy single value (?severity=critical, ?priority=P0 from dashboard links)
  // parses as a one-item list, so old links keep working; 'all' is ignored.
  const [severityParam, setSeverityParam] = useUrlFilterList('severity')
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [bulkResolveOpen, setBulkResolveOpen] = useState(false)
  const [bulkResolveNote, setBulkResolveNote] = useState('')
  const [findingToDelete, setFindingToDelete] = useState<Finding | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [importDialogOpen, setImportDialogOpen] = useState(false)
  const [statusParam, setStatusParam] = useUrlFilterList('status')
  // Multiple sources at once: "everything from code scanning" is one question,
  // and it spans sast and secret. Comma-separated, matching what the API takes.
  const [sourceFilter, setSourceFilter] = useUrlFilterList('source')
  // CTEM signals are independent, stackable filters — each lives in its own URL
  // param so "P0 AND reachable AND KEV" is one link, not three mutually-exclusive
  // choices. The backend FindingFilter ANDs priority_classes + is_in_kev +
  // is_reachable + sla_status, so the UI param model must let them coexist.
  //  - `priority` : the P0–P3 class (single value)
  //  - `kev`      : boolean flag → is_in_kev
  //  - `reachable`: boolean flag → is_reachable
  //  - `sla_status`: multi-select list → sla_status
  const [priorityParam, setPriorityParam] = useUrlFilterList('priority_class')
  const [kevFilter, setKevFilter] = useUrlFilter('is_in_kev', 'false')
  const [reachableFilter, setReachableFilter] = useUrlFilter('is_reachable', 'false')
  // Findings seen only on a feature branch are not exposure: the list leaves
  // them out unless this is on (then it shows only them).
  const [branchOnlyFilter, setBranchOnlyFilter] = useUrlFilter('branch_only', 'false')
  const [slaFilter, setSlaFilter] = useUrlFilterList('sla_status')
  // Set by the Pending approval and Accepted · expiring quick views.
  const [pendingApprovalParam, setPendingApprovalParam] = useUrlFilter('pending_approval', '')
  const [acceptanceExpiresParam, setAcceptanceExpiresParam] = useUrlFilter(
    'acceptance_expires_at_lte',
    ''
  )
  const pendingApprovalFilter =
    pendingApprovalParam === 'true' ? true : pendingApprovalParam === 'false' ? false : undefined
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  // The state lens (Open, the default · Fixed · Dispositioned · All). A saved
  // view carries its own status scope, so the default lens is not laid on top
  // of one; a lens picked explicitly still is.
  const rawLens = useUrlParam('state')
  const [, setLensParam] = useUrlFilter('state', DEFAULT_FINDING_LENS)
  const lens = parseFindingLens(rawLens)
  // "Assigned to me" / My Work: findings the current user is the assignee of,
  // owns the asset of, or is a member of an assigned group. Independent, stackable
  // with the CTEM signals; the backend resolves the user from the token.
  const [relatedToFilter, setRelatedToFilter] = useUrlFilter('related_to', '')
  const mineActive = relatedToFilter === 'me'
  const setMineFilter = useCallback(
    (on: string) => setRelatedToFilter(on === 'true' ? 'me' : ''),
    [setRelatedToFilter]
  )

  // Old page links (assetId, sources, priority, kev, reachable, mine, cve,
  // rule, a table-format sort) are rewritten to the API names once, in place.
  useEffect(() => {
    const migrated = migrateLegacyParams(
      new URLSearchParams(window.location.search),
      FINDINGS_LEGACY_URL_ALIASES,
      SORTABLE_COLUMNS
    )
    if (!migrated) return
    replaceUrlSearch(migrated)
  }, [])
  const kevActive = kevFilter === 'true'
  const reachableActive = reachableFilter === 'true'
  const branchOnlyActive = branchOnlyFilter === 'true'
  const severities = useMemo(
    () =>
      severityParam.filter((v): v is FacetSeverity =>
        (SEVERITY_LEVELS as readonly string[]).includes(v)
      ),
    [severityParam]
  )
  const statuses = useMemo(() => statusParam.filter((v) => v !== 'all'), [statusParam])
  const priorityClasses = useMemo(
    () => priorityParam.filter((v) => /^p[0-3]$/i.test(v)).map((v) => v.toUpperCase()),
    [priorityParam]
  )

  // Debounce so typing doesn't fire a backend list request per keystroke.
  const debouncedSearch = useDebounce(searchQuery, 300)
  // Server-side pagination state. The list is fetched one page at a time from
  // the API (was: fetch first 100 + client-paginate, which capped the table at
  // 100 rows even when the tenant had thousands of findings).
  // The whole view is in the URL — tab, page, page size and sort as well as
  // filters — so any screen of this list can be shared or bookmarked.
  const list = useListParams({ pageSizes: PAGE_SIZES, defaultPageSize: 20 })
  const { pagination, setPagination, setPage } = list
  // No tabs: grouping is a view of the same findings ("Group by"), and the
  // verification queue is reached from its metric. Legacy ?tab= links map over.
  const [tabParam, setTabParam] = useUrlFilter('tab', '')
  const [groupParam, setGroupParam] = useUrlFilter('group', '')
  const [viewParam, setViewParam] = useUrlFilter('view', '')
  useEffect(() => {
    if (tabParam === 'groups') setGroupParam('cve_id')
    if (tabParam === 'pending') setViewParam('verify')
    if (tabParam) setTabParam('')
  }, [tabParam, setTabParam, setGroupParam, setViewParam])
  const groupBy = (GROUP_BY_DIMENSIONS as string[]).includes(groupParam)
    ? (groupParam as GroupByDimension)
    : null
  const verifyView = viewParam === 'verify'
  // A saved view (D15) lives in the same param as its id; the API applies its
  // filter, with any filter in the URL on top, as the viewer.
  const savedId = savedViewId(viewParam)
  // Opening a saved view replaces the URL's filters with the view (and its
  // grouping); clearing it goes back to the plain list.
  const openSavedView = useCallback((view: SavedView | null) => {
    if (!view) {
      replaceUrlSearch(new URLSearchParams())
      return
    }
    const q = new URLSearchParams({ view: view.id })
    if (view.group_by) q.set('group', view.group_by)
    replaceUrlSearch(q)
  }, [])
  // The view is "modified" when filters in the URL sit on top of it.
  const savedViewModified =
    !!savedId &&
    Array.from(searchParams.keys()).some(
      (k) => !['view', 'group', 'page', 'per_page', 'tab', 'density'].includes(k)
    )

  // asset_id and scan_id (a scan run's "View all findings") are read above.
  // A CVE group's "View": the list narrowed to that CVE (search does not match
  // the CVE id, so it cannot stand in for this).
  const [cveParam] = useUrlFilter('cve_id', '')
  // A rule group's "View": the list narrowed to that scanner rule (nuclei
  // template, semgrep rule, misconfiguration check, secret rule).
  const [ruleParam] = useUrlFilter('rule_id', '')
  // The other group dimensions' drill-down filters (research 24 P0-1): every
  // group row's View opens the list narrowed to it.
  const [familyParam] = useUrlFilter('family', '')
  const [findingTypeParam] = useUrlFilter('finding_type', '')
  const [componentParam] = useUrlFilter('component_id', '')
  const [ownerParam] = useUrlFilter('asset_owner_id', '')
  const [ownerNullParam] = useUrlFilter('asset_owner_id_null', '')
  // An asset group's links (its findings tab, its severity breakdown).
  const [assetGroupParam] = useUrlFilter('asset_group_id', '')
  // The dashboard's "crown jewels exposed" (findings on crown jewels).
  const [crownJewelParam] = useUrlFilter('asset_crown_jewel', '')
  const crownJewelActive = crownJewelParam === 'true'
  const ownerUnassigned = ownerNullParam === 'true'
  // Bumped after a change, so the grouped view reloads its groups and rows.
  const [groupsReloadKey, setGroupsReloadKey] = useState(0)
  const [autoAssignOpen, setAutoAssignOpen] = useState(false)
  const [hasUnassignedGroup, setHasUnassignedGroup] = useState(false)
  const [sortParam, setSortParam] = useUrlFilter('sort', '')
  const sorting = useMemo<SortingState>(() => parseSortParam(sortParam), [sortParam])
  // The URL holds the API sort (e.g. `-created_at` or `severity,-created_at`).
  const handleSortingChange = useCallback(
    (next: SortingState) => setSortParam(toApiSort(next) ?? ''),
    [setSortParam]
  )
  // Filter panel: closed by default so the table gets the width; the viewer's
  // choice is remembered (a per-browser convenience, safe to lose).
  const [filtersOpen, setFiltersOpenState] = useState(false)
  useEffect(() => {
    try {
      if (window.localStorage.getItem(FILTERS_OPEN_KEY) === '1') setFiltersOpenState(true)
    } catch {
      // storage unavailable — stay closed
    }
  }, [])
  const setFiltersOpen = useCallback((next: boolean | ((open: boolean) => boolean)) => {
    setFiltersOpenState((prev) => {
      const value = typeof next === 'function' ? next(prev) : next
      try {
        window.localStorage.setItem(FILTERS_OPEN_KEY, value ? '1' : '0')
      } catch {
        // best-effort
      }
      return value
    })
  }, [])
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  // "Hide informational": a saved per-browser view preference. It applies only
  // while no severity is picked; an explicit severity choice always wins.
  const [hideInfo, setHideInfoState] = useState(false)
  useEffect(() => {
    try {
      if (window.localStorage.getItem(HIDE_INFO_KEY) === '1') setHideInfoState(true)
    } catch {
      // storage unavailable — show everything
    }
  }, [])
  const setHideInfo = useCallback((value: boolean) => {
    setHideInfoState(value)
    try {
      window.localStorage.setItem(HIDE_INFO_KEY, value ? '1' : '0')
    } catch {
      // best-effort
    }
  }, [])
  const effectiveSeverities = useMemo<FacetSeverity[]>(
    () => (severities.length > 0 ? severities : hideInfo ? [...ACTIONABLE_SEVERITIES] : []),
    [severities, hideInfo]
  )
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [markFixedGroup, setMarkFixedGroup] = useState<FindingGroup | null>(null)
  const [ticketFinding, setTicketFinding] = useState<Finding | null>(null)
  // Findings selected to spin up (or join) a remediation task. Non-null = dialog open.
  const [remedFindings, setRemedFindings] = useState<{ id: string; title: string }[] | null>(null)
  const { hasPermission } = usePermissions()
  // The gate of POST /findings/imports (the API stays authoritative).
  const canImport =
    hasPermission('findings:write') &&
    hasPermission('assets:write') &&
    hasPermission('assets:import')
  // Both are Phase-3 gated modules embedded in this (findings) page: the "Create
  // Jira Ticket" action hits the integrations module, and "Add to remediation"
  // hits the remediation module. Hide + skip-fetch when disabled (fail-open on
  // OSS where no modules are reported).
  const remediationEnabled = useModuleEnabled('remediation')
  // "Create task from these filters": the list filter becomes query text on
  // the server (the same filter registry), then the query-task dialog opens.
  const canQueryTask =
    remediationEnabled &&
    hasPermission(Permission.RemediationWrite) &&
    hasPermission(Permission.FindingsRead)
  const [taskQuery, setTaskQuery] = useState<{ query: string; ignored: string[] } | null>(null)
  const canCreateTicket = useCanCreateTicket()
  // The row menu offers a change only to someone the API lets make it (the
  // gates of POST /findings/{id}/assign and PATCH /findings/{id}/status).
  const canAssignOne = hasPermission(Permission.FindingsAssign)
  const canChangeStatusOne = hasPermission(Permission.FindingsStatus)

  // Statuses hidden from default dashboard view (pentest WIP, not ready for visibility)
  const HIDDEN_STATUSES = useMemo(() => [...FINDINGS_LIST_HIDDEN_STATUSES], [])

  // Build API filters
  // The source catalog is data, not a hardcoded list. The previous inline list
  // had drifted: it omitted cspm, which live findings actually use, so those
  // findings could not be filtered for at all.
  // Fetched when the Source filter is opened (or a source is already picked),
  // not with every page load.
  const [sourcesWanted, setSourcesWanted] = useState(false)
  const { data: sourceCatalog } = useFindingSourcesApi(
    undefined,
    sourcesWanted || sourceFilter.length > 0
  )

  const sourceGroups = useMemo(() => {
    const grouped = groupFindingSourcesByCategory(sourceCatalog?.data ?? [])
    return Array.from(grouped.entries()).map(([code, group]) => ({
      code,
      label: group.label,
      options: group.options,
      codes: group.options.map((o) => o.value),
    }))
  }, [sourceCatalog?.data])

  const toggleSource = useCallback(
    (code: string) => {
      // Functional update, not a read of `sourceFilter` from render scope: two
      // toggles resolved against the same snapshot would lose the first.
      setSourceFilter((prev) =>
        prev.includes(code) ? prev.filter((c) => c !== code) : [...prev, code]
      )
    },
    [setSourceFilter]
  )

  const toggleSla = useCallback(
    (code: string) => {
      setSlaFilter((prev) =>
        prev.includes(code) ? prev.filter((c) => c !== code) : [...prev, code]
      )
    },
    [setSlaFilter]
  )

  // Any filter change resets to the first page — otherwise a user on page 8 of
  // "All" who picks a filter with only 2 pages would sit on an empty page.
  // Keyed on the filter *values*, so the first render (reading a shared link
  // with ?page=3) is not reset — only a later filter change is.
  // Filters in the URL that the page does not draw itself (an EPSS floor, a
  // port, a tag...). They go to the API as they are; the filter contract names
  // them, so it is loaded when the URL holds one, or when the picker opens.
  const unownedParams = useMemo(
    () =>
      Array.from(new Set(searchParams.keys())).filter(
        (k) =>
          !NON_FILTER_PARAMS.has(k) && !OWNED_FILTER_PARAMS.has(k) && !CONTEXT_FILTER_PARAMS.has(k)
      ),
    [searchParams]
  )
  const [pickerOpen, setPickerOpen] = useState(false)
  const {
    contract: loadedContract,
    isLoading: contractLoading,
    error: contractError,
  } = useFindingFilterContract(pickerOpen || unownedParams.length > 0)
  const filterContract = useMemo(() => withOwnedFields(loadedContract), [loadedContract])
  const unknownParams = useMemo(
    () =>
      loadedContract
        ? readFilters(searchParams, filterContract, CONTEXT_FILTER_PARAMS).unknown
        : [],
    [loadedContract, filterContract, searchParams]
  )
  const extraParams = useMemo(() => {
    const extra: Record<string, string> = {}
    for (const k of unownedParams) {
      // Once the contract is known, a param it does not know is shown as an
      // unknown filter and kept out of the request, so the list still loads.
      if (unknownParams.includes(k)) continue
      const v = searchParams.get(k)
      if (v) extra[k] = v
    }
    return extra
  }, [unownedParams, unknownParams, searchParams])
  const extraKey = JSON.stringify(extraParams)

  const filterKey = [
    assetIdFilter,
    scanIdFilter,
    cveParam,
    ruleParam,
    familyParam,
    findingTypeParam,
    componentParam,
    ownerParam,
    ownerNullParam,
    assetGroupParam,
    crownJewelActive,
    groupParam,
    viewParam,
    lens,
    effectiveSeverities.join(),
    statuses.join(),
    sourceFilter.join(),
    priorityClasses.join(),
    kevActive,
    reachableActive,
    branchOnlyActive,
    mineActive,
    slaFilter.join(),
    pendingApprovalParam,
    acceptanceExpiresParam,
    extraKey,
    debouncedSearch,
    sortParam,
  ].join('|')
  // The rows a selection was made on: one page of one filtered, sorted list.
  // Any change of page, page size, filter, search, sort or view starts with
  // nothing selected, so a bulk action only ever reaches rows on screen.
  const selectionScope = `${pagination.pageIndex}|${pagination.pageSize}|${filterKey}`
  useEffect(() => {
    setSelectedFindings((prev) => (prev.length > 0 ? [] : prev))
  }, [selectionScope])

  // The filter the current page number belongs to. While a new filter waits
  // for its page reset (the effect below), the list already asks page 1:
  // asking the old page first sent the list request twice (research/81).
  // Recorded only once the URL is this page's: a key taken from the previous
  // page's params would read as a filter change and reset a linked ?page=3.
  const [pagedFilterKey, setPagedFilterKey] = useState<string | null>(null)
  const filterChanged = pagedFilterKey !== null && pagedFilterKey !== filterKey
  useEffect(() => {
    if (!urlSettled) return
    if (pagedFilterKey === null) {
      setPagedFilterKey(filterKey)
      return
    }
    if (!filterChanged) return
    setPagedFilterKey(filterKey)
    setPage(1)
  }, [urlSettled, pagedFilterKey, filterChanged, filterKey, setPage])

  const apiFilters = useMemo((): FindingApiFilters => {
    const filters: FindingApiFilters = {
      page: filterChanged ? 1 : pagination.pageIndex + 1,
      per_page: pagination.pageSize,
    }
    if (assetIdFilter) filters.asset_id = assetIdFilter
    if (scanIdFilter) filters.scan_id = scanIdFilter
    if (cveParam) filters.cve_ids = [cveParam]
    if (ruleParam) filters.rule_id = ruleParam
    if (familyParam) filters.families = [familyParam]
    if (findingTypeParam) filters.finding_types = [findingTypeParam]
    if (componentParam) filters.component_id = componentParam
    if (ownerParam) filters.asset_owner_id = ownerParam
    if (ownerUnassigned) filters.asset_owner_unassigned = true
    if (assetGroupParam) filters.asset_group_id = assetGroupParam
    if (crownJewelActive) filters.asset_crown_jewel = true
    if (effectiveSeverities.length > 0) filters.severities = effectiveSeverities
    if (savedId) filters.view = savedId
    if (!savedId || rawLens) filters.state = lens
    if (statuses.length > 0) {
      filters.statuses = statuses as NonNullable<FindingApiFilters['statuses']>
    } else if (!savedId) {
      // (A saved view carries its own status scope.)
      // Default: exclude draft/in_review (pentest WIP not ready for dashboard)
      filters.exclude_statuses = HIDDEN_STATUSES
    }
    if (sourceFilter.length > 0) {
      filters.sources = sourceFilter as NonNullable<FindingApiFilters['sources']>
    }
    if (debouncedSearch.trim()) {
      filters.search = debouncedSearch.trim()
    }
    // CTEM prioritization filters (RFC-017) — independent and stackable. Each
    // applies together (AND), mirroring how the backend FindingFilter combines
    // PriorityClasses + IsInKEV + IsReachable + SLAStatuses.
    if (priorityClasses.length > 0) filters.priority_classes = priorityClasses
    if (sortParam) filters.sort = sortParam
    if (kevActive) filters.is_in_kev = true
    if (reachableActive) filters.is_reachable = true
    if (branchOnlyActive) filters.branch_only = true
    if (mineActive) filters.assigned_to_me = true
    if (slaFilter.length > 0) filters.sla_statuses = slaFilter
    if (pendingApprovalFilter !== undefined) filters.pending_approval = pendingApprovalFilter
    if (Object.keys(extraParams).length > 0) filters.extra = extraParams
    if (acceptanceExpiresParam) filters.acceptance_expires_at_lte = acceptanceExpiresParam
    return filters
  }, [
    assetIdFilter,
    scanIdFilter,
    cveParam,
    ruleParam,
    familyParam,
    findingTypeParam,
    componentParam,
    ownerParam,
    ownerUnassigned,
    assetGroupParam,
    crownJewelActive,
    effectiveSeverities,
    statuses,
    sourceFilter,
    priorityClasses,
    kevActive,
    reachableActive,
    branchOnlyActive,
    mineActive,
    slaFilter,
    pendingApprovalFilter,
    acceptanceExpiresParam,
    extraParams,
    debouncedSearch,
    HIDDEN_STATUSES,
    pagination,
    filterChanged,
    sortParam,
    savedId,
    lens,
    rawLens,
  ])

  // The stats describe the page's scope: every finding the caller may see
  // (their data scope applies server-side), narrowed only by the context
  // filters the page was opened with (an asset, a scan run, a CVE or rule
  // group's "View", the other group drill-downs). They give the empty state
  // its organization total and the count of findings the filters hide; the
  // sidebar's quick views carry the per-view counts. The key holds no facet,
  // search or state, so filtering sends no stats request (research/81).
  const overviewStatsFilters = useMemo(
    (): FindingStatsFilters => ({
      state: 'all',
      exclude_statuses: HIDDEN_STATUSES,
      asset_id: apiFilters.asset_id,
      scan_id: apiFilters.scan_id,
      cve_ids: apiFilters.cve_ids,
      rule_id: apiFilters.rule_id,
      families: apiFilters.families,
      finding_types: apiFilters.finding_types,
      component_id: apiFilters.component_id,
      asset_owner_id: apiFilters.asset_owner_id,
      asset_owner_unassigned: apiFilters.asset_owner_unassigned,
      asset_group_id: apiFilters.asset_group_id,
      asset_crown_jewel: apiFilters.asset_crown_jewel,
    }),
    [HIDDEN_STATUSES, apiFilters]
  )
  // The context filters as the chips read them.
  const contextFilterValues = {
    assetId: assetIdFilter,
    scanId: scanIdFilter,
    cveId: cveParam,
    ruleId: ruleParam,
    family: familyParam,
    findingType: findingTypeParam,
    componentId: componentParam,
    ownerId: ownerParam,
    ownerUnassigned,
    assetGroupId: assetGroupParam,
    crownJewel: crownJewelActive,
  }
  const hasContextScope = hasFindingContextFilters(contextFilterValues)
  // keepPreviousData: a context change keeps the numbers until the new ones arrive.
  const {
    data: findingStats,
    isLoading: statsLoading,
    mutate: mutateOverviewStats,
  } = useFindingStatsApi(overviewStatsFilters, { enabled: urlSettled, keepPreviousData: true })
  const statsFailed = !findingStats && !statsLoading
  // A change moves findings between views: the sidebar counts reload with the stats.
  const { data: quickViewData } = useFindingQuickViews(urlSettled)
  const mutateStats = useCallback(
    () => Promise.all([mutateOverviewStats(), refreshFindingQuickViews()]),
    [mutateOverviewStats]
  )

  // The flat list. The grouped and verification views render their own rows,
  // so the flat page is not fetched while one of them is shown.
  const {
    data: findingsResponse,
    error,
    isLoading: findingsLoading,
    isValidating: findingsValidating,
    mutate: mutateFindingsList,
  } = useFindingsApi(apiFilters, {
    keepPreviousData: true,
    enabled: urlSettled && !groupBy && !verifyView,
    // The failure shows inline in the table area (with Retry); the default
    // handler would add a toast saying the same thing.
    onError: () => {},
  })
  // Every refresh after a change also reloads the grouped view's groups and rows.
  const mutateFindings = useCallback(() => {
    setGroupsReloadKey((k) => k + 1)
    return mutateFindingsList()
  }, [mutateFindingsList])

  // Transform API data to UI format
  const findings = useMemo(() => {
    if (!findingsResponse?.data) return []
    return findingsResponse.data.map(transformApiToUiFinding)
  }, [findingsResponse])

  const selectedCount = selectedFindingIds.length
  // Bulk actions need findings:bulk_update and the single-item permission of
  // each action (the API checks both); selection is offered only when at least
  // one bulk action is.
  const canBulkUpdate = hasPermission(Permission.FindingsBulkUpdate)
  const canBulkAssign = canBulkUpdate && hasPermission(Permission.FindingsAssign)
  const canBulkStatus = canBulkUpdate && hasPermission(Permission.FindingsStatus)
  const canBulkRemediate = hasPermission('findings:remediation:write') && remediationEnabled
  const canSelect = canBulkAssign || canBulkStatus || canBulkRemediate
  // One bulk write at a time (a double click must not send two).
  const [bulkBusy, setBulkBusy] = useState(false)

  const handleRefresh = async () => {
    // Each request once: the list, the stats and the sidebar counts. (A blanket
    // invalidation of every /findings key here sent all of them a second time.)
    await Promise.all([mutateFindings(), mutateStats()])
    toast.success(t('findings.toast.refreshed', 'Findings refreshed'))
  }

  const openTaskFromFilters = useCallback(async () => {
    const endpoint = buildFindingsEndpoint(apiFilters)
    const params = endpoint.includes('?') ? endpoint.slice(endpoint.indexOf('?') + 1) : ''
    try {
      setTaskQuery(await taskQueryApi.fromFilters(params))
    } catch {
      setTaskQuery({ query: '', ignored: [] })
    }
  }, [apiFilters])
  // Export runs on the server only (findings:export): every finding the
  // filter selects, in the list's sort, scoped and audit-logged, up to the
  // cap the API states. Without the permission there is no Export control.
  const canExport = hasPermission(Permission.FindingsExport)
  const [exporting, setExporting] = useState(false)
  const handleExport = async (format: 'csv' | 'ndjson') => {
    if (exporting) return
    setExporting(true)
    try {
      const { maxRows } = await downloadFindingsExport(
        buildFindingsExportUrl(apiFilters, format),
        format
      )
      const listTotal = findingsResponse?.total
      if (exportTruncated(listTotal, maxRows)) {
        toast.warning(
          t('findings.export.truncated', 'Exported the first {max} of {total} findings', {
            max: (maxRows ?? 0).toLocaleString(),
            total: (listTotal ?? 0).toLocaleString(),
          }),
          {
            description: t(
              'findings.export.truncatedHint',
              'One export holds at most {max} findings. Narrow the filters to export the rest.',
              { max: (maxRows ?? 0).toLocaleString() }
            ),
          }
        )
      } else {
        toast.success(t('findings.export.done', 'Export downloaded'))
      }
    } catch (error) {
      const status = (error as { statusCode?: unknown }).statusCode
      if (status === 403) {
        toast.error(t('findings.export.forbidden', 'You cannot export findings'), {
          description:
            describePermissionDenied(errorDetails(error)) ??
            t(
              'findings.export.forbiddenHint',
              'Exporting needs the Export findings permission. Ask an organization administrator.'
            ),
        })
      } else if (status === 429) {
        toast.error(t('findings.export.busy', 'An export of yours is still running'), {
          description: t('findings.export.busyHint', 'Wait for it to finish, then try again.'),
        })
      } else {
        toast.error(
          getErrorMessage(error, t('findings.export.failed', 'The export failed. Try again.'))
        )
      }
    } finally {
      setExporting(false)
    }
  }

  // Bulk endpoints answer 200 even when the server refused some findings (for
  // example a change to false positive that needs approval), so the toast is
  // driven by the reported counts.
  const showBulkResult = (summary: BulkSummary) => {
    const opts = summary.description ? { description: summary.description } : undefined
    if (summary.kind === 'success') toast.success(summary.message, opts)
    else if (summary.kind === 'warning') toast.warning(summary.message, opts)
    else toast.error(summary.message, opts)
  }

  const handleBulkAssign = async (userId: string) => {
    const findingIds = selectedFindingIds
    if (findingIds.length === 0 || !userId.trim() || bulkBusy) return

    setBulkBusy(true)
    try {
      // post() answers STEP_UP_REQUIRED with the shared re-authentication
      // dialog and retries once, and turns an error body into a message.
      const result = await post<BulkFindingResult>('/api/v1/findings/bulk/assign', {
        finding_ids: findingIds,
        user_id: userId.trim(),
      })
      showBulkResult(summarizeBulkResult(result, findingIds.length, 'Assigned'))
      clearSelection()
      mutateFindings()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.bulk.assignFailed', 'Failed to assign findings'))
      )
    } finally {
      setBulkBusy(false)
    }
  }

  /** Returns whether the write went through (a failed bulk resolve keeps its note). */
  const handleBulkStatusChange = async (status: string, resolution?: string): Promise<boolean> => {
    if (selectedFindingIds.length === 0 || bulkBusy) return false

    setBulkBusy(true)
    try {
      // Dry run first (the API's transition engine): only the findings that
      // may move are sent; the others are reported with the reason.
      const dryRun = summarizeDryRun(
        t,
        await evaluateFindingTransitions(selectedFindingIds, status),
        { note: resolution }
      )
      const refusedText = dryRun.refused.map((r) => `${r.reason} (${r.count})`).join('; ')
      if (dryRun.allowed.length === 0) {
        toast.error(t('findings.bulk.noneCanMove', 'None of the selected findings can move'), {
          description: refusedText,
        })
        return false
      }
      if (dryRun.refused.length > 0) {
        toast.warning(
          t('findings.bulk.someCannotMove', '{count} of the selected findings cannot move', {
            count: selectedFindingIds.length - dryRun.allowed.length,
          }),
          { description: refusedText }
        )
      }
      const findingIds = dryRun.allowed
      // post() answers STEP_UP_REQUIRED (a bulk move to a closing status) with
      // the shared re-authentication dialog and retries once.
      const result = await post<BulkFindingResult>('/api/v1/findings/bulk/status', {
        finding_ids: findingIds,
        status,
        resolution,
      })
      showBulkResult(summarizeBulkResult(result, findingIds.length, 'Updated'))
      clearSelection()
      mutateFindings()
      mutateStats()
      return true
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.bulk.statusFailed', 'Failed to update findings'))
      )
      return false
    } finally {
      setBulkBusy(false)
    }
  }

  const handleRowClick = useCallback((finding: Finding) => {
    setSelectedFinding(finding)
    setDrawerOpen(true)
  }, [])

  // j / k move through the list while the drawer is open; the open finding
  // is in the URL hash so the address can be shared and reopens it.
  useDrawerKeyboardNav({
    open: drawerOpen,
    items: findings,
    currentId: selectedFinding?.id,
    onSelect: setSelectedFinding,
  })
  const [deepLinkId] = useState(() => readFindingHash())
  const { data: deepLinked } = useFindingApi(deepLinkId && !selectedFinding ? deepLinkId : null)
  useEffect(() => {
    if (deepLinked && !selectedFinding) {
      setSelectedFinding(transformApiToUiFinding(deepLinked))
      setDrawerOpen(true)
    }
  }, [deepLinked, selectedFinding])
  useEffect(() => {
    writeFindingHash(drawerOpen && selectedFinding ? selectedFinding.id : null)
  }, [drawerOpen, selectedFinding])

  // The drawer writes status, severity and assignee itself (with its own toast
  // and Undo); the page only refreshes the list. Writing again here sent every
  // change twice and showed two toasts.
  const refreshAfterDrawerChange = useCallback(() => {
    mutateFindings()
    mutateStats()
  }, [mutateFindings, mutateStats])

  const handleDeleteClick = (finding: Finding) => {
    setFindingToDelete(finding)
    setDeleteDialogOpen(true)
  }

  const handleDeleteConfirm = async () => {
    if (!findingToDelete) return

    setIsDeleting(true)
    try {
      // del() answers STEP_UP_REQUIRED with the shared re-authentication dialog.
      await del(`/api/v1/findings/${encodeURIComponent(findingToDelete.id)}`)

      toast.success(t('findings.toast.deleted', 'Finding deleted'), {
        description: findingToDelete.title,
      })
      setDeleteDialogOpen(false)
      setFindingToDelete(null)
      mutateFindings()
      mutateStats()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.toast.deleteFailed', 'Failed to delete finding'))
      )
    } finally {
      setIsDeleting(false)
    }
  }

  // Open the "remediate findings" dialog, pre-filled from the selection: the name
  // is derived from the finding(s) and the priority from the highest severity, so
  // the mobilise step is one click from where a finding lives.
  const openRemediationFor = useCallback((selected: Finding[]) => {
    if (selected.length === 0) return
    setRemedFindings(selected.map((f) => ({ id: f.id, title: f.title })))
  }, [])

  const handleRowAction = useCallback(
    (action: FindingRowAction, finding: Finding) => {
      switch (action) {
        case 'view':
          handleRowClick(finding)
          break
        case 'remediate':
          openRemediationFor([finding])
          break
        case 'copy_id':
          copyToClipboard(finding.id)
          toast.success(t('findings.toast.idCopied', 'Finding ID copied to clipboard'))
          break
        case 'copy_link':
          copyToClipboard(`${window.location.origin}/findings/${finding.id}`)
          toast.success(t('findings.toast.linkCopied', 'Link copied to clipboard'))
          break
        case 'delete':
          handleDeleteClick(finding)
          break
        case 'create_ticket':
          setTicketFinding(finding)
          break
        case 'assign':
        case 'status':
        case 'false_positive':
          // These actions live in the detail drawer (assignee picker, status
          // select with approval flow). Open it focused on this finding rather
          // than firing a no-op.
          handleRowClick(finding)
          break
      }
    },
    [handleRowClick, openRemediationFor, t]
  )

  // Define columns for DataTable
  // Priority is the RFC-004 P0–P3 class; it's only populated once the
  // classifier has run. When nothing in view has one, we drop the column
  // instead of rendering a full column of "—" (it returns once data exists).
  const hasAnyPriority = useMemo(() => findings.some((f) => f.priorityClass), [findings])

  const columns: ColumnDef<Finding>[] = useMemo(() => {
    const cols: ColumnDef<Finding>[] = [
      {
        id: 'select',
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && 'indeterminate')
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label={t('findings.list.selectAll', 'Select all rows on this page')}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={t('findings.list.selectRow', 'Select finding {title}', {
              title: toDisplayText(row.original.title, 80),
            })}
            onClick={(e) => e.stopPropagation()}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      },
      {
        accessorKey: 'title',
        meta: { label: t('findings.columns.title', 'Title') },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('findings.columns.title', 'Title')} />
        ),
        cell: ({ row }) => {
          // Use hasDataFlow flag from API (populated via subquery in list view)
          // Fall back to checking dataFlow object for detail view compatibility
          const hasDataFlow =
            row.original.hasDataFlow || (row.original.dataFlow?.steps.length ?? 0) > 0

          return (
            <div
              className="cursor-pointer max-w-[200px] sm:max-w-[260px] 2xl:max-w-md"
              role="button"
              tabIndex={0}
              // The title leads the name, so a screen reader announces which
              // finding the button opens (it used to read "View finding
              // details" on every row).
              aria-label={`${toDisplayText(row.getValue('title'), 300)}, view details`}
              onClick={() => handleRowClick(row.original)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  handleRowClick(row.original)
                }
              }}
            >
              <div className="flex items-center gap-1.5">
                {/* Scanner-supplied text: escaped, isolated, never markup. */}
                <p dir="auto" className="font-medium truncate [unicode-bidi:isolate]">
                  {toDisplayText(row.getValue('title'), 500)}
                </p>
                {row.original.branchOnly && <BranchOnlyBadge />}
                {/* KEV — actively exploited; the single most urgent triage signal */}
                {row.original.isInKev && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="inline-flex shrink-0 items-center gap-0.5 rounded-full bg-red-600 px-1.5 py-0.5 text-[10px] font-semibold text-white">
                        <AlertOctagon className="h-2.5 w-2.5" />
                        {t('findings.list.kev', 'KEV')}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-xs text-xs">
                      <p className="font-semibold">
                        {t('findings.list.kevTitle', 'CISA Known Exploited Vulnerability')}
                      </p>
                      {row.original.kevDueDate && (
                        <p>
                          {t('findings.list.kevDue', 'Remediate by {date}', {
                            date: new Date(row.original.kevDueDate).toLocaleDateString(),
                          })}
                        </p>
                      )}
                    </TooltipContent>
                  </Tooltip>
                )}
                {typeof row.original.epssScore === 'number' && row.original.epssScore > 0 && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="inline-flex shrink-0 items-center rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
                        {t('findings.list.epss', 'EPSS {score}', {
                          score: formatEpssScore(row.original.epssScore),
                        })}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-xs text-xs">
                      {t(
                        'findings.list.epssHint',
                        'Exploit Prediction Scoring System — estimated probability of exploitation in the next 30 days'
                      )}
                    </TooltipContent>
                  </Tooltip>
                )}
                {hasDataFlow && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="inline-flex items-center gap-0.5 rounded-full bg-blue-500/20 px-1.5 py-0.5 text-[10px] font-medium text-blue-400 shrink-0">
                        <Route className="h-2.5 w-2.5" />
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="text-xs">
                      {t('findings.list.attackPath', 'Has attack path data')}
                    </TooltipContent>
                  </Tooltip>
                )}
              </div>
              {(row.original.cve || row.original.scanner) && (
                <p className="text-muted-foreground truncate text-xs">
                  {row.original.cve && <span className="font-mono">{row.original.cve}</span>}
                  {row.original.cve && row.original.scanner && ' · '}
                  {row.original.scanner}
                </p>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'severity',
        meta: { label: t('findings.columns.severity', 'Severity') },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.columns.severity', 'Severity')}
          />
        ),
        cell: ({ row }) => <SeverityBadge severity={row.getValue('severity')} />,
        filterFn: (row, id, value) => {
          return value.includes(row.getValue(id))
        },
      },
      {
        accessorKey: 'priorityClass',
        meta: { label: t('findings.columns.priority', 'Priority') },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.columns.priority', 'Priority')}
          />
        ),
        cell: ({ row }) => {
          const pc = row.original.priorityClass
          if (!pc) return <span className="text-muted-foreground text-xs">-</span>
          return <PriorityClassBadge priorityClass={pc} />
        },
        filterFn: (row, id, value) => {
          return value.includes(row.getValue(id))
        },
      },
      {
        id: 'source',
        meta: { label: t('findings.columns.source', 'Source') },
        accessorFn: (row) => row.source || '-',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('findings.columns.source', 'Source')} />
        ),
        cell: ({ row }) => (
          <Badge variant="outline" className="text-xs uppercase">
            {row.getValue('source')}
          </Badge>
        ),
      },
      {
        id: 'asset',
        meta: { label: t('findings.list.location') },
        enableSorting: false,
        accessorFn: (row) => row.assets[0]?.name || '-',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('findings.list.location')} />
        ),
        cell: ({ row }) => {
          const asset = row.original.assets[0]
          const loc = row.original.location
          if (loc && (loc.asset || loc.detail)) {
            // Asset on top, the place on it below, cut from the middle so the
            // part that differs between two findings (the end of a path or
            // URL) stays visible; the full value is in the tooltip.
            return (
              <div className="flex min-w-0 max-w-[240px] flex-col">
                {loc.asset && (
                  <TruncatedText
                    value={loc.asset}
                    label={t('findings.list.asset')}
                    className="text-sm"
                  />
                )}
                {loc.detail && (
                  <TruncatedText
                    value={loc.detail}
                    label={t('findings.list.location')}
                    middle={30}
                    className={cn(
                      'font-mono text-muted-foreground',
                      loc.asset ? 'text-xs' : 'text-sm'
                    )}
                  />
                )}
              </div>
            )
          }
          // No asset name and no location: show a compact link to the asset
          // instead of the bare UUID, which reads as broken data.
          if (asset?.id) {
            return (
              <Link
                href={`/assets/${asset.id}`}
                title={asset.id}
                className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm hover:underline"
              >
                <ExternalLink className="h-3 w-3 shrink-0" />
                <span className="font-mono">{asset.id.slice(0, 8)}…</span>
              </Link>
            )
          }
          return <span className="text-muted-foreground text-sm">—</span>
        },
      },
      {
        accessorKey: 'status',
        meta: { label: t('findings.columns.status', 'Status') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('findings.columns.status', 'Status')} />
        ),
        cell: ({ row }) => (
          <span className="inline-flex flex-wrap items-center gap-1">
            <FindingStatusBadge status={row.getValue('status')} />
            <FindingSubStatus subStatusId={row.original.subStatusId} />
          </span>
        ),
        filterFn: (row, id, value) => {
          return value.includes(row.getValue(id))
        },
      },
      {
        accessorKey: 'slaStatus',
        meta: { label: t('findings.columns.sla', 'Due / SLA') },
        enableSorting: true,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('findings.columns.sla', 'Due / SLA')} />
        ),
        cell: ({ row }) => {
          const status = row.original.slaStatus
          if (!status || status === 'not_applicable') {
            return <span className="text-muted-foreground text-sm">—</span>
          }
          return (
            <div className="flex flex-col gap-0.5">
              <SlaStatusBadge status={status} />
              {row.original.slaDeadline && (
                <span className="text-muted-foreground text-xs tabular-nums">
                  {formatDueRelative(row.original.slaDeadline)}
                </span>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'createdAt',
        meta: { label: t('findings.columns.created', 'Created') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('findings.columns.created', 'Created')} />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm">
            {new Date(row.getValue('createdAt')).toLocaleDateString()}
          </span>
        ),
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => {
          const finding = row.original
          return (
            <FindingRowMenu
              title={finding.title}
              onAction={(action) => handleRowAction(action, finding)}
              canAssign={canAssignOne}
              canChangeStatus={canChangeStatusOne}
              canCreateTicket={canCreateTicket}
              canRemediate={hasPermission('findings:remediation:write') && remediationEnabled}
              canDelete={hasPermission('findings:delete')}
            />
          )
        },
      },
    ]
    // No bulk action for this user: no selection checkboxes either.
    const shown = canSelect ? cols : cols.filter((c) => c.id !== 'select')
    return hasAnyPriority
      ? shown
      : shown.filter((c) => !('accessorKey' in c) || c.accessorKey !== 'priorityClass')
  }, [
    handleRowAction,
    handleRowClick,
    hasPermission,
    hasAnyPriority,
    canSelect,
    remediationEnabled,
    canCreateTicket,
    canAssignOne,
    canChangeStatusOne,
    t,
  ])

  // ---- Filter model shared by the facet panel, the chips and the metrics ----
  const setSeverities = (next: string[]) => setSeverityParam(next)
  const toggleIn = (list: string[], value: string) =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value]

  // A plain function, not useCallback: this block sits below the early `error`
  // return, so a hook here would be conditional.
  const clearAllFilters = () => {
    setSeverityParam([])
    setStatusParam([])
    setPriorityParam([])
    setKevFilter('false')
    setReachableFilter('false')
    setBranchOnlyFilter('false')
    setSlaFilter([])
    setSourceFilter([])
    // Filters the page does not draw itself: every one of them goes.
    if (unownedParams.length > 0) {
      const next = new URLSearchParams(window.location.search)
      for (const k of unownedParams) next.delete(k)
      replaceUrlSearch(next)
    }
    setMineFilter('false')
    setPendingApprovalParam('')
    setAcceptanceExpiresParam('')
    setSearchQuery('')
  }

  const statusLabel = (v: string) => {
    const cfg = FINDING_STATUS_CONFIG[v as FindingStatus]
    if (!cfg) return v.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
    return t(cfg.labelKey, cfg.label)
  }

  const activeCount =
    Number(mineActive) +
    severities.length +
    statuses.length +
    priorityClasses.length +
    Number(kevActive) +
    Number(reachableActive) +
    Number(branchOnlyActive) +
    Number(pendingApprovalParam !== '') +
    Number(acceptanceExpiresParam !== '') +
    unownedParams.length +
    slaFilter.length +
    sourceFilter.length

  const facetPanel = (
    <FacetPanel activeCount={activeCount} onClearAll={clearAllFilters}>
      <FacetToggle
        label={t('findings.facet.assignedToMe', 'Assigned to me')}
        description={t(
          'findings.facet.assignedToMeHint',
          "Yours, on assets you own, or your team's"
        )}
        checked={mineActive}
        onCheckedChange={(v) => setMineFilter(v ? 'true' : 'false')}
      />
      <FacetSection
        title={t('findings.facet.severity', 'Severity')}
        selectedCount={severities.length}
      >
        {SEVERITY_LEVELS.map((v) => (
          <FacetOption
            key={v}
            label={severityLabel(v)}
            checked={severities.includes(v)}
            onCheckedChange={() => setSeverities(toggleIn(severities, v))}
            adornment={
              <span className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT_COLORS[v])} />
            }
          />
        ))}
      </FacetSection>
      <FacetToggle
        label={t('findings.hideInformational', 'Hide informational')}
        description={t(
          'findings.hideInformational.hint',
          'Hide info findings from the list. Saved on this browser.'
        )}
        checked={hideInfo}
        onCheckedChange={setHideInfo}
      />
      <FacetSection
        title={t('findings.facet.priority', 'Priority')}
        selectedCount={priorityClasses.length + (kevActive ? 1 : 0) + (reachableActive ? 1 : 0)}
      >
        {PRIORITY_OPTIONS.map((o) => (
          <FacetOption
            key={o.value}
            label={
              <>
                {o.value}{' '}
                <span className="text-muted-foreground">
                  · {t(`findings.priority.hint.${o.value}`, o.hint)}
                </span>
              </>
            }
            checked={priorityClasses.includes(o.value)}
            onCheckedChange={() => setPriorityParam(toggleIn(priorityClasses, o.value))}
          />
        ))}
        <FacetGroupLabel>{t('findings.facet.threatSignals', 'Threat signals')}</FacetGroupLabel>
        <FacetOption
          label={t('findings.facet.kev', 'In CISA KEV')}
          checked={kevActive}
          onCheckedChange={(v) => setKevFilter(v ? 'true' : 'false')}
        />
        <FacetOption
          label={t('findings.facet.reachable', 'Reachable')}
          checked={reachableActive}
          onCheckedChange={(v) => setReachableFilter(v ? 'true' : 'false')}
        />
      </FacetSection>
      <FacetSection title={t('findings.facet.status', 'Status')} selectedCount={statuses.length}>
        {STATUS_GROUPS.map((g) => (
          <div key={g.key}>
            <FacetGroupLabel
              onSelectAll={() => setStatusParam(Array.from(new Set([...statuses, ...g.values])))}
            >
              {t(`findings.statusCategory.${g.key}`, g.label)}
            </FacetGroupLabel>
            {g.values.map((v) => (
              <FacetOption
                key={v}
                label={statusLabel(v)}
                checked={statuses.includes(v)}
                onCheckedChange={() => setStatusParam(toggleIn(statuses, v))}
              />
            ))}
          </div>
        ))}
      </FacetSection>
      <FacetSection
        title={t('findings.facet.sla', 'SLA')}
        selectedCount={slaFilter.length}
        defaultOpen={false}
      >
        {SLA_OPTIONS.map((v) => (
          <FacetOption
            key={v}
            label={t(`findings.sla.${v}`, SLA_STATUS_LABELS[v])}
            checked={slaFilter.includes(v)}
            onCheckedChange={() => toggleSla(v)}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('findings.facet.branch', 'Branch')}
        selectedCount={branchOnlyActive ? 1 : 0}
        defaultOpen={branchOnlyActive}
      >
        <FacetOption
          label={t('findings.facet.featureBranchOnly', 'Only on a feature branch')}
          checked={branchOnlyActive}
          onCheckedChange={(v) => setBranchOnlyFilter(v ? 'true' : 'false')}
        />
      </FacetSection>
      <FacetSection
        title={t('findings.facet.source', 'Source')}
        selectedCount={sourceFilter.length}
        defaultOpen={false}
        onOpenChange={(open) => open && setSourcesWanted(true)}
      >
        {sourceGroups.length === 0 ? (
          <p className="py-1 text-xs text-muted-foreground">
            {t('findings.facet.noSources', 'No sources yet.')}
          </p>
        ) : (
          sourceGroups.map((g) => (
            <div key={g.code}>
              <FacetGroupLabel
                onSelectAll={() =>
                  setSourceFilter(Array.from(new Set([...sourceFilter, ...g.codes])))
                }
              >
                {g.label}
              </FacetGroupLabel>
              {g.options.map((o) => (
                <FacetOption
                  key={o.value}
                  label={o.label}
                  checked={sourceFilter.includes(o.value)}
                  onCheckedChange={() => toggleSource(o.value)}
                />
              ))}
            </div>
          ))
        )}
      </FacetSection>
    </FacetPanel>
  )

  const facetPanelScrollable = <div className="flex min-h-0 flex-1 flex-col">{facetPanel}</div>

  // The grouped views do not load the flat page; the tab count is the same number.
  const total = findingsResponse?.total ?? 0
  // The view this list is: a built-in quick view when the URL is exactly one,
  // a saved view, or a custom combination of filters.
  const activeQuickView = knownQuickViews(quickViewData?.views).find((v) =>
    quickViewIsActive(searchParams, v)
  )
  const viewTitle = activeQuickView
    ? t(
        quickViewLabelKey(activeQuickView.key),
        QUICK_VIEW_LABELS[activeQuickView.key as QuickViewKey]
      )
    : savedId
      ? t('findings.view.saved', 'Saved view')
      : lens === 'all' && activeCount === 0
        ? t('findings.view.all', 'All findings')
        : t('findings.view.custom', 'Custom view')
  const awaitingVerification = findingStats?.awaiting_verification ?? 0
  // Which kind of empty this is: from the organization's total (scope-only
  // stats), the filters the person set, the search, and a refused read.
  const emptyKind = findingsEmptyKind({
    orgTotal: statsFailed ? undefined : findingStats?.by_state?.all,
    filterCount: activeCount,
    hasSearch: searchQuery.trim() !== '',
    hasContextScope,
    forbidden: accessStateOf(error) === 'no_access',
  })
  // Findings of the viewed state that the filters and search hide.
  const hiddenByFilters = findingStats?.by_state?.[lens]
  const denialText = describePermissionDenied(errorDetails(error)) ?? undefined

  const filterButtons = (
    <FilterPanelToggle
      open={filtersOpen}
      onToggle={() => setFiltersOpen((o) => !o)}
      onOpenSheet={() => setFilterSheetOpen(true)}
      activeCount={activeCount}
      controlsId="finding-filters"
    />
  )

  // The filter button and the search box are one control: the button is
  // joined to the start of the field, so they never separate when the row is
  // tight, and the field takes all the width the row has left.
  const filterSearch = (
    <div
      data-testid="findings-filter-search"
      className="flex min-w-0 flex-1 items-center [&_[data-slot=filter-button]]:z-10 [&_[data-slot=filter-button]]:rounded-e-none"
    >
      {filterButtons}
      <div className="relative -ms-px min-w-40 flex-1">
        <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder={t(
            'findings.toolbar.searchPlaceholder',
            'Search title, CVE, rule or location…'
          )}
          aria-label={t('findings.toolbar.searchLabel', 'Search findings')}
          className="h-9 rounded-s-none ps-9 focus-visible:z-20"
        />
      </div>
    </div>
  )

  const groupBySelect = (
    <Select
      value={groupBy ?? 'none'}
      onValueChange={(v) => {
        setViewParam('')
        setGroupParam(v === 'none' ? '' : v)
      }}
    >
      <SelectTrigger
        className="h-9 w-auto gap-2 @2xl/toolbar:min-w-36"
        aria-label={t('findings.toolbar.groupLabel', 'Group findings')}
      >
        <Layers className="h-4 w-4 text-muted-foreground" />
        <span className="sr-only @2xl/toolbar:not-sr-only">
          <SelectValue />
        </span>
      </SelectTrigger>
      <SelectContent align="end">
        <SelectItem value="none">{t('findings.toolbar.groupNone', 'Group')}</SelectItem>
        {GROUP_BY_DIMENSIONS.map((d) => (
          <SelectItem key={d} value={d}>
            {t(GROUP_BY_LABEL_KEYS[d], GROUP_BY_LABELS[d])}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          className="h-9 w-9"
          onClick={handleRefresh}
          disabled={statsLoading || findingsLoading}
          aria-label={t('findings.toolbar.refresh', 'Refresh')}
        >
          <RefreshCw
            className={cn('h-4 w-4', (statsLoading || findingsLoading) && 'animate-spin')}
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{t('findings.toolbar.refresh', 'Refresh')}</TooltipContent>
    </Tooltip>
  )

  const exportItems = (
    <>
      <DropdownMenuItem disabled={exporting} onClick={() => void handleExport('csv')}>
        {t('findings.toolbar.exportCsv', 'Export as CSV')}
      </DropdownMenuItem>
      <DropdownMenuItem disabled={exporting} onClick={() => void handleExport('ndjson')}>
        {t('findings.toolbar.exportJson', 'Export as JSON')}
      </DropdownMenuItem>
    </>
  )
  const exportMenu = canExport ? (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-9" disabled={exporting}>
          {exporting ? (
            <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />
          ) : (
            <Download className="me-2 h-4 w-4" aria-hidden />
          )}
          {t('findings.toolbar.export', 'Export')}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">{exportItems}</DropdownMenuContent>
    </DropdownMenu>
  ) : null

  const taskFromFiltersButton = canQueryTask ? (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="h-9"
          onClick={() => void openTaskFromFilters()}
        >
          <SquareCode className="me-2 h-4 w-4" aria-hidden />
          {t('remediationQuery.findings.fromFiltersShort')}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{t('remediationQuery.findings.fromFilters')}</TooltipContent>
    </Tooltip>
  ) : null

  // Narrow list: the page actions fold into one menu, so the state lens and
  // refresh keep their row instead of pushing a control onto a new line.
  const moreActionsMenu = (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="icon"
              className="h-9 w-9"
              aria-label={t('findings.toolbar.moreActions', 'More actions')}
            >
              <MoreHorizontal className="h-4 w-4" aria-hidden />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>{t('findings.toolbar.moreActions', 'More actions')}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end">
        {canQueryTask && (
          <DropdownMenuItem onClick={() => void openTaskFromFilters()}>
            <SquareCode className="me-2 h-4 w-4" aria-hidden />
            {t('remediationQuery.findings.fromFiltersShort')}
          </DropdownMenuItem>
        )}
        {canQueryTask && canExport && <DropdownMenuSeparator />}
        {canExport && exportItems}
      </DropdownMenuContent>
    </DropdownMenu>
  )

  // Filters that arrive from elsewhere (an asset, a scan run, a CVE or rule
  // group) are context, not facets: always shown, in their own row under the
  // toolbar (never inside it, where a chip made the toolbar row taller and
  // moved its end controls). They come from the URL, so the row is there from
  // the first frame. Each chip removes only its own parameter.
  const removeContextParam = (param: string) =>
    replaceUrlSearch(removeFilterParam(new URLSearchParams(window.location.search), param))
  const contextChips = hasContextScope ? (
    <FindingContextChips {...contextFilterValues} onRemove={removeContextParam} />
  ) : undefined

  const { views: savedViewList } = useSavedViews('findings', !!savedId)
  const openView = savedViewList.find((v) => v.id === savedId)
  const filterBar = (
    <FilterBar
      search={searchParams}
      contract={filterContract}
      pickerContract={loadedContract}
      contractLoading={contractLoading}
      contractFailed={!!contractError}
      skip={CONTEXT_FILTER_PARAMS}
      viewFilter={openView?.filter}
      canReadAssets={hasPermission(Permission.AssetsRead)}
      leading={contextChips}
      onPickerOpenChange={setPickerOpen}
      onSearchChange={replaceUrlSearch}
    />
  )

  const toolbarStart = filterSearch

  // Second row (the table toolbar): which rows and how they show. Saved views
  // and Group sit beside the search they work with; the table's own View menu
  // ends the row.
  const toolbarEnd = (
    <>
      <SavedViewsMenu
        page="findings"
        activeId={savedId}
        modified={savedViewModified}
        groupBy={groupParam}
        onSelect={openSavedView}
      />
      {groupBySelect}
    </>
  )

  // First row: which view this is and how many findings it holds, then the
  // page actions. It never wraps: below 42rem of list width the actions fold
  // into "More actions". DOM order = visual order = tab order: view,
  // verification queue, refresh, export, task.
  const primaryRow = (
    <div
      data-testid="findings-toolbar-primary"
      className="@container/actions flex items-center gap-2"
    >
      <div className="flex min-w-0 items-center gap-3">
        <h2
          data-testid="findings-view-title"
          className="min-w-0 truncate text-sm font-medium"
          title={viewTitle}
        >
          {viewTitle}
        </h2>
        {!groupBy && (
          <span
            className="shrink-0 text-sm tabular-nums text-muted-foreground"
            aria-label={t(
              'findings.view.total',
              '{count, plural, one {# finding} other {# findings}}',
              {
                count: total,
              }
            )}
          >
            {total.toLocaleString()}
          </span>
        )}
        {awaitingVerification > 0 && hasPermission(Permission.FindingsVerify) && (
          <Button
            variant="outline"
            size="sm"
            className="h-8 shrink-0"
            onClick={() => setViewParam('verify')}
          >
            {t('findings.view.awaitingVerification', 'Awaiting verification')}
            <span className="ms-2 tabular-nums text-muted-foreground">
              {awaitingVerification.toLocaleString()}
            </span>
          </Button>
        )}
      </div>
      <div className="ms-auto flex shrink-0 items-center gap-2">
        {groupBy === 'owner_id' && hasUnassignedGroup && (
          <Button
            variant="outline"
            size="sm"
            className="h-9"
            onClick={() => setAutoAssignOpen(true)}
          >
            <UserPlus className="h-4 w-4 @2xl/actions:me-2" />
            <span className="sr-only @2xl/actions:not-sr-only">
              {t('findings.toolbar.assignOwners', 'Assign to asset owners')}
            </span>
          </Button>
        )}
        {refreshButton}
        {!groupBy && (
          <>
            <div className="hidden items-center gap-2 @2xl/actions:flex">
              {exportMenu}
              {taskFromFiltersButton}
            </div>
            {(canQueryTask || canExport) && (
              <div className="@2xl/actions:hidden">{moreActionsMenu}</div>
            )}
          </>
        )}
      </div>
    </div>
  )

  // Phone layout of a finding row (list and grouped views alike): a card with
  // the row's checkbox and menu.
  const mobileRow = (f: Finding, selection: MobileRowSelection) => (
    <FindingPhoneCard
      finding={f}
      selection={selection}
      onOpen={handleRowClick}
      menu={
        <FindingRowMenu
          title={f.title}
          onAction={(action) => handleRowAction(action, f)}
          canAssign={canAssignOne}
          canChangeStatus={canChangeStatusOne}
          canCreateTicket={canCreateTicket}
          canRemediate={hasPermission('findings:remediation:write') && remediationEnabled}
          canDelete={hasPermission('findings:delete')}
        />
      }
    />
  )

  // "View" on a group opens the list filtered to it, for every dimension
  // (research 24 P0-1). It is a push, not a replace: Back returns to the
  // grouped view with its filters, and the other filters are kept.
  const viewableGroup = groupBy !== null
  const viewGroup = (group: FindingGroup) => {
    if (!groupBy) return
    pushUrlSearch(
      buildDrillDownSearch(new URLSearchParams(window.location.search), groupBy, group.group_key)
    )
  }

  // Mark fixed works on a CVE's or an asset's in-progress findings (the
  // fix-applied action filters by CVE or asset only).
  const canMarkFixed = hasPermission(Permission.FindingsFixApply)
  const groupActions = (group: FindingGroup) => (
    <>
      {viewableGroup && (
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2"
          onClick={() => viewGroup(group)}
          aria-label={t('findings.group.viewLabel', 'View the findings of {label}', {
            label: group.label,
          })}
        >
          {t('findings.group.view', 'View')}
        </Button>
      )}
      {canMarkFixed &&
        (group.group_type === 'cve' || group.group_type === 'asset') &&
        (group.stats?.in_progress ?? 0) > 0 && (
          <Button
            variant="outline"
            size="sm"
            className="h-7 px-2"
            onClick={() => setMarkFixedGroup(group)}
          >
            {t('findings.group.markFixed', 'Mark fixed')}
          </Button>
        )}
    </>
  )
  const canVerify = hasPermission(Permission.FindingsVerify)
  const verifyActions = (group: FindingGroup) =>
    canVerify ? <VerifyGroupActions group={group} onDone={refreshAfterDrawerChange} /> : null

  // Grouped by severity or source, every row would repeat its group's value.
  const groupColumnId = groupBy === 'severity' ? 'severity' : groupBy === 'source' ? 'source' : ''
  const groupedColumns = groupColumnId
    ? columns.filter(
        (c) => c.id !== groupColumnId && !('accessorKey' in c && c.accessorKey === groupColumnId)
      )
    : columns
  const groupedProps = {
    columns: groupedColumns,
    toRow: transformApiToUiFinding,
    pagination,
    onPaginationChange: setPagination,
    pageSizeOptions: PAGE_SIZES,
    onRowClick: handleRowClick,
    onSelectionChange: setSelectedFindings,
    // A new grouping or view starts with nothing selected.
    resetSelectionKey: `${selectionEpoch}|${selectionScope}`,
    mobileRow,
    reloadKey: groupsReloadKey,
  }

  // Breadcrumb of a drill-down, rebuilt from the URL: Findings › By rule › X.
  const drillDim = drillOrigin(searchParams, GROUP_BY_DIMENSIONS)
  const drillBreadcrumb = drillDim ? (
    <DrillDownBreadcrumb
      className="mt-1"
      steps={[
        {
          label: t('findings.page.title', 'Findings'),
          onSelect: () => pushUrlSearch(new URLSearchParams()),
        },
        {
          label: t('findings.drill.by', 'By {dimension}', {
            dimension: t(GROUP_BY_LABEL_KEYS[drillDim], GROUP_BY_LABELS[drillDim]).toLowerCase(),
          }),
          onSelect: () => pushUrlSearch(buildGroupedSearch(searchParams, drillDim)),
        },
      ]}
      value={drillValue(searchParams, drillDim)}
      mono={drillDim === 'cve_id' || drillDim === 'rule_id'}
    />
  ) : undefined

  return (
    <>
      <Main>
        <PageHeader title={t('findings.page.title', 'Findings')} description={drillBreadcrumb}>
          <Button variant="outline" size="sm" asChild>
            <Link href="/findings/approvals">
              <ClipboardList className="h-4 w-4 sm:me-2" />
              <span className="sr-only sm:not-sr-only">
                {t('findings.header.approvals', 'Approvals')}
              </span>
            </Link>
          </Button>
          {canImport && (
            <Button
              variant="outline"
              size="sm"
              aria-label={t('findings.header.importResults', 'Import results')}
              onClick={() => setImportDialogOpen(true)}
            >
              <FileUp className="h-4 w-4 sm:me-2" />
              <span className="sr-only sm:not-sr-only">
                {t('findings.header.importResults', 'Import results')}
              </span>
            </Button>
          )}
          {hasPermission('findings:write') && (
            <Button
              size="sm"
              aria-label={t('findings.header.addFinding', 'Add finding')}
              onClick={() => setCreateDialogOpen(true)}
            >
              <Plus className="h-4 w-4 sm:me-2" />
              <span className="sr-only sm:not-sr-only">
                {t('findings.header.addFinding', 'Add finding')}
              </span>
            </Button>
          )}
        </PageHeader>

        <>
          <div className="mt-5 flex items-start">
            {/* Always mounted so opening and closing can animate: the slot's
                width (and the gap after it) eases between 0 and the card's
                width while the card fades, and the table beside it resizes in
                step. The card keeps its own width, so its contents never
                reflow mid-animation. */}
            <div
              inert={!filtersOpen}
              className={cn(
                'sticky top-4 hidden shrink-0 overflow-hidden transition-[width,margin-inline-end,opacity] duration-300 ease-in-out motion-reduce:transition-none lg:block',
                filtersOpen ? 'me-5 w-64 opacity-100' : 'me-0 w-0 opacity-0'
              )}
            >
              <aside
                id="finding-filters"
                aria-label={t('findings.filters.title', 'Finding filters')}
                // A self-contained floating card, as tall as the viewport and
                // pinned while the page scrolls: its length no longer depends
                // on the table's, and long filter lists scroll inside it.
                className="flex h-[calc(100svh-7.5rem)] w-64 flex-col rounded-xl border bg-card p-4 shadow-sm"
              >
                {facetPanelScrollable}
              </aside>
            </div>

            <div className="min-w-0 flex-1 space-y-3">
              {!urlSettled ? (
                <Skeleton className="h-9 w-80 max-w-full" />
              ) : !verifyView ? (
                primaryRow
              ) : null}
              {!urlSettled ? (
                // The render before the address bar holds this page's URL:
                // nothing here is real yet, and nothing is fetched.
                <FindingsTableSkeleton />
              ) : verifyView ? (
                <FindingGroupsTable
                  {...groupedProps}
                  dimension="cve_id"
                  statuses="fix_applied"
                  renderGroupActions={verifyActions}
                  toolbarStart={
                    <>
                      <Button variant="ghost" size="sm" onClick={() => setViewParam('')}>
                        <ArrowLeft className="me-2 h-4 w-4" />
                        {t('findings.verify.all', 'All findings')}
                      </Button>
                      <span className="text-sm text-muted-foreground">
                        {t('findings.verify.title', 'Fixes awaiting verification, by CVE')}
                      </span>
                    </>
                  }
                  toolbarEnd={refreshButton}
                  emptyMessage={t('findings.verify.empty', 'No fixes awaiting verification')}
                  emptyDescription={t(
                    'findings.verify.emptyHint',
                    'Fixes that owners mark as applied wait here for a verifier.'
                  )}
                />
              ) : groupBy ? (
                <FindingGroupsTable
                  {...groupedProps}
                  dimension={groupBy}
                  query={apiFilters}
                  renderGroupActions={groupActions}
                  onViewGroup={viewableGroup ? viewGroup : undefined}
                  onGroupsLoaded={(groups) =>
                    setHasUnassignedGroup(groups.some((g) => g.group_key === 'unassigned'))
                  }
                  toolbarStart={toolbarStart}
                  toolbarBelow={filterBar}
                  toolbarEnd={toolbarEnd}
                  emptyDescription={
                    activeCount > 0
                      ? t(
                          'findings.empty.tryRemoving',
                          'Try removing a filter or clearing them all.'
                        )
                      : undefined
                  }
                />
              ) : !findingsResponse && findingsLoading ? (
                <FindingsTableSkeleton contextChips={filterBar} />
              ) : (
                <>
                  <div
                    role={findingsValidating ? 'progressbar' : undefined}
                    aria-label={
                      findingsValidating
                        ? t('findings.list.refreshing', 'Refreshing findings')
                        : undefined
                    }
                    className="-mb-1 h-0.5 overflow-hidden rounded-full"
                  >
                    {findingsValidating && (
                      <div className="h-full w-1/3 animate-pulse rounded-full bg-primary motion-reduce:animate-none" />
                    )}
                  </div>
                  <DataTable
                    columns={columns}
                    data={findings}
                    showSearch={false}
                    toolbarStart={toolbarStart}
                    toolbarEnd={toolbarEnd}
                    toolbarBelow={filterBar}
                    getRowId={(f) => f.id}
                    manualPagination
                    rowCount={total}
                    pagination={pagination}
                    onPaginationChange={setPagination}
                    pageSizeOptions={PAGE_SIZES}
                    sorting={sorting}
                    onSortingChange={handleSortingChange}
                    onSelectionChange={setSelectedFindings}
                    resetSelectionKey={`${selectionEpoch}|${selectionScope}`}
                    onRowClick={handleRowClick}
                    mobileRow={mobileRow}
                    initialColumnVisibility={DEFAULT_HIDDEN_COLUMNS}
                    showSelectionCount={false}
                    emptyState={
                      <FindingsEmptyState
                        kind={emptyKind}
                        hiddenCount={
                          typeof hiddenByFilters === 'number' ? hiddenByFilters : undefined
                        }
                        stateLabel={t(lensLabelKey(lens), lens)}
                        filterCount={activeCount}
                        hasSearch={searchQuery.trim() !== ''}
                        canImport={canImport}
                        canSetUpScan={hasPermission(Permission.ScansRead)}
                        canOpenIntegrations={hasPermission(Permission.IntegrationsRead)}
                        onImport={() => setImportDialogOpen(true)}
                        onClearFilters={clearAllFilters}
                        onSearchAllStates={lens !== 'all' ? () => setLensParam('all') : undefined}
                        denial={denialText}
                      />
                    }
                    errorState={
                      error && invalidFilterParams(error) ? (
                        <InvalidFilterNotice
                          params={invalidFilterParams(error) ?? []}
                          onRemove={(names) => {
                            const next = new URLSearchParams(window.location.search)
                            for (const n of names) next.delete(n)
                            next.delete('page')
                            replaceUrlSearch(next)
                          }}
                        />
                      ) : error && accessStateOf(error) !== 'no_access' ? (
                        <ErrorState
                          title={t('findings.list.errorTitle', 'findings')}
                          error={error}
                          onRetry={() => void mutateFindings()}
                        />
                      ) : undefined
                    }
                  />
                </>
              )}
            </div>
          </div>

          {canSelect && (
            <BulkActionBar count={selectedCount} onClear={clearSelection}>
              {canBulkAssign && (
                <AssigneeSelect
                  placeholder={t('findings.bulk.assignTo', 'Assign to…')}
                  disabled={bulkBusy}

                  onChange={(user) => {
                    if (user) void handleBulkAssign(user.id)
                  }}
                />
              )}

              {canBulkRemediate && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => openRemediationFor(selectedFindings)}
                >
                  <Wrench className="me-2 h-4 w-4" />
                  {t('remediationClaim.menu.bulk')}
                </Button>
              )}

              {canBulkStatus && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm" disabled={bulkBusy}>
                      {bulkBusy ? (
                        <Loader2 className="me-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Flag className="me-2 h-4 w-4" />
                      )}
                      {t('findings.bulk.status', 'Status')}
                    </Button>
                  </DropdownMenuTrigger>

                  <DropdownMenuContent side="top" align="center">
                    <DropdownMenuItem onClick={() => void handleBulkStatusChange('confirmed')}>
                      {t('findings.status.confirmed', 'Confirmed')}
                    </DropdownMenuItem>

                    <DropdownMenuItem onClick={() => void handleBulkStatusChange('in_progress')}>
                      {t('findings.status.in_progress', 'In Progress')}
                    </DropdownMenuItem>

                    {/* Resolving needs findings:verify; the API refuses it otherwise. */}
                    {hasPermission(Permission.FindingsVerify) && (
                      <DropdownMenuItem onSelect={() => setBulkResolveOpen(true)}>
                        {t('findings.status.resolved', 'Resolved')}
                      </DropdownMenuItem>
                    )}

                    {/* false_positive requires the per-finding approval flow, so it is

                    intentionally not offered as a bulk action. */}
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </BulkActionBar>
          )}

          <FilterSheet
            open={filterSheetOpen}
            onOpenChange={setFilterSheetOpen}
            title={t('findings.filters.title', 'Finding filters')}
            resultLabel={t(
              'findings.filters.show',
              'Show {count, plural, one {# finding} other {# findings}}',
              { count: total }
            )}
          >
            {facetPanel}
          </FilterSheet>
        </>
      </Main>

      {/* Mark Fixed Dialog */}
      {markFixedGroup && (
        <MarkFixedDialog
          open={!!markFixedGroup}
          onOpenChange={(open) => {
            if (!open) setMarkFixedGroup(null)
          }}
          groupKey={markFixedGroup.group_key}
          groupType={markFixedGroup.group_type}
          groupLabel={markFixedGroup.label}
          findingCount={markFixedGroup.stats.in_progress}
          onSuccess={() => {
            setMarkFixedGroup(null)
            mutateFindings()
            mutateStats()
          }}
        />
      )}

      <AutoAssignDialog
        open={autoAssignOpen}
        onOpenChange={setAutoAssignOpen}
        onSuccess={() => mutateFindings()}
      />

      {/* Create Jira Ticket Dialog */}
      {ticketFinding && (
        <CreateTicketDialog
          findingId={ticketFinding.id}
          findingTitle={ticketFinding.title}
          open={!!ticketFinding}
          onOpenChange={(open) => {
            if (!open) setTicketFinding(null)
          }}
        />
      )}

      {/* Task from the list's filters: mounted only while open. */}
      {canQueryTask && taskQuery && (
        <CreateTaskFromQueryDialog
          open
          onOpenChange={(o) => {
            if (!o) setTaskQuery(null)
          }}
          initialQuery={taskQuery.query}
          ignoredFilters={taskQuery.ignored}
        />
      )}

      {/* Mounted only while open: the dialog reads members, groups, tasks and
          campaigns, so keeping it always-mounted would fire those (gated-module)
          requests on every Findings page load. */}
      {remedFindings && (
        <AddFindingsToTaskDialog
          open
          onOpenChange={(open) => {
            if (!open) setRemedFindings(null)
          }}
          findings={remedFindings}
          onDone={clearSelection}
        />
      )}

      {/* Finding Quick View Drawer */}
      <FindingDetailDrawer
        finding={selectedFinding}
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        onStatusChange={refreshAfterDrawerChange}
        onSeverityChange={refreshAfterDrawerChange}
        onAssigneeChange={refreshAfterDrawerChange}
      />

      {/* Create Finding Dialog */}
      <CreateFindingDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSuccess={() => {
          mutateFindings()
          mutateStats()
        }}
      />

      {/* Import results from other tools */}
      <ImportResultsDialog
        open={importDialogOpen}
        onOpenChange={setImportDialogOpen}
        onImported={() => {
          mutateFindings()
          mutateStats()
        }}
      />

      {/* Bulk resolve: closes every selected finding at once. */}
      <ConfirmDialog
        open={bulkResolveOpen}
        onOpenChange={setBulkResolveOpen}
        title={
          selectedFindingIds.length === 1
            ? t('confirm.finding.bulkResolveTitleOne', 'Resolve 1 finding?')
            : t('confirm.finding.bulkResolveTitle', 'Resolve {count} findings?', {
                count: selectedFindingIds.length,
              })
        }
        desc={t(
          'confirm.finding.bulkResolveDesc',
          'The selected findings are closed as resolved and leave the open work queues and SLA tracking.'
        )}
        confirmText={t('confirm.finding.resolve', 'Resolve')}
        disabled={!bulkResolveNote.trim() || bulkBusy}
        handleConfirm={async () => {
          if (await handleBulkStatusChange('resolved', bulkResolveNote.trim())) {
            setBulkResolveNote('')
            setBulkResolveOpen(false)
          }
        }}
      >
        {/* A bulk resolve reads no verification checklist: it is attested and needs a note. */}
        <div className="space-y-2">
          <Label htmlFor="bulk-resolve-note">
            {t('findings.statusNote.label', 'Note (required)')}
          </Label>
          <Textarea
            id="bulk-resolve-note"
            value={bulkResolveNote}
            maxLength={1000}
            rows={3}
            placeholder={t(
              'findings.statusNote.placeholder',
              'e.g. Upgraded the library to 4.2 in release 2026.10'
            )}
            onChange={(e) => setBulkResolveNote(e.target.value)}
          />
        </div>
      </ConfirmDialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.finding.deleteTitle', 'Delete this finding?')}
        desc={t(
          'confirm.finding.deleteDesc',
          'The finding is permanently deleted with its comments, activity and evidence. This cannot be undone.'
        )}
        confirmText={
          isDeleting ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.deleting', 'Deleting…')}
            </>
          ) : (
            t('confirm.delete', 'Delete')
          )
        }
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDeleteConfirm}
      >
        {findingToDelete && (
          <div className="rounded-lg border bg-muted/50 p-3 my-2">
            <p className="font-medium truncate">{findingToDelete.title}</p>
            <p className="text-sm text-muted-foreground">
              {t('findings.delete.severity', '{severity} severity', {
                severity: (findingToDelete.severity in SEVERITY_DOT_COLORS
                  ? severityLabel(findingToDelete.severity as SeverityLevel)
                  : findingToDelete.severity
                ).toUpperCase(),
              })}
              {findingToDelete.scanner && ` · ${findingToDelete.scanner}`}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </>
  )
}
