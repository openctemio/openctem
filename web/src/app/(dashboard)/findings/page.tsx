'use client'

import { useListParams } from '@/hooks/use-list-params'
import { summarizeBulkResult, type BulkSummary } from '@/features/findings/lib/bulk-result'
import { buildCsv, downloadCsv } from '@/hooks/use-csv-export'
import { formatEpssScore } from '@/lib/epss'
import { useState, useMemo, useCallback, useEffect, type ReactNode } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  DEFAULT_FINDING_LENS,
  FINDING_LENSES,
  parseFindingLens,
  type FindingLens,
} from '@/features/findings/lib/state-lens'
import { findingsOverview } from '@/features/findings/lib/findings-overview'
import {
  useUrlParams,
  useUrlParam,
  useUrlFilter,
  useUrlFilterList,
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
  MetricStrip,
  type MetricStripItem,
  FacetPanel,
  FacetSection,
  FacetOption,
  FacetToggle,
  FacetGroupLabel,
  BulkActionBar,
  FilterPanelToggle,
  FilterSheet,
  TruncatedText,
  SegmentedLens,
  DrillDownBreadcrumb,
} from '@/features/shared'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import {
  ACTIONABLE_SEVERITIES,
  SEVERITY_LEVELS,
  highestSeverity,
  type SeverityLevel,
} from '@/lib/severity'
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
import {
  Download,
  RefreshCw,
  MoreHorizontal,
  UserPlus,
  Flag,
  CheckCircle,
  ExternalLink,
  Trash2,
  Copy,
  Link2,
  Plus,
  FileUp,
  AlertCircle,
  Loader2,
  Route,
  ClipboardList,
  AlertOctagon,
  Ticket,
  Wrench,
  Search,
  ArrowLeft,
  Layers,
  ChevronRight,
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
import { LinkFindingsToRemediationDialog } from '@/features/remediation/components/link-findings-dialog'
import { VerifyGroupActions } from '@/features/findings/components/verify-group-actions'
import { type FindingGroup } from '@/features/findings/api/use-finding-groups'
import {
  useFindingsApi,
  useFindingStatsApi,
  buildFindingsExportUrl,
  invalidateFindingsCache,
} from '@/features/findings/api/use-findings-api'
import { ConfirmDialog } from '@/components/confirm-dialog'
import type { ApiFinding, FindingApiFilters } from '@/features/findings/api/finding-api.types'
import type { Finding, FindingStatus } from '@/features/findings'
import type { Severity } from '@/features/shared/types'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { csrfFetch } from '@/lib/api/client'
import { usePermissions } from '@/context/permission-provider'
import { ImportResultsDialog } from '@/features/findings/components/import-results-dialog'
import { Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { findingAssetType } from '@/features/findings/lib/finding-asset-type'
import { FINDINGS_LEGACY_URL_ALIASES, migrateLegacyParams } from '@/lib/filters/url-codec'
import { SavedViewsMenu } from '@/features/saved-views/components/saved-views-menu'
import { savedViewId, type SavedView } from '@/features/saved-views/api/use-saved-views'
import { FINDINGS_LIST_HIDDEN_STATUSES } from '@/features/findings/lib/list-defaults'

// ============================================
// Transform API Finding to UI Finding
// ============================================

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
    title: api.title || api.rule_name || api.message,
    description: api.description || api.snippet || api.message,
    severity: api.severity as Severity,
    status: api.status as FindingStatus,
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
    dataFlow: api.data_flow
      ? {
          sources: api.data_flow.sources?.map((loc) => ({
            path: loc.path,
            line: loc.line,
            column: loc.column,
            content: loc.content,
            label: loc.label,
          })),
          intermediates: api.data_flow.intermediates?.map((loc) => ({
            path: loc.path,
            line: loc.line,
            column: loc.column,
            content: loc.content,
            label: loc.label,
          })),
          sinks: api.data_flow.sinks?.map((loc) => ({
            path: loc.path,
            line: loc.line,
            column: loc.column,
            content: loc.content,
            label: loc.label,
          })),
        }
      : undefined,
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
const OVERDUE_SLA = ['overdue', 'exceeded']
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
 * so they sit in the same toolbar row before and after the rows load.
 */
function FindingsTableSkeleton({ contextChips }: { contextChips?: ReactNode }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-1 flex-wrap items-center gap-2">
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-72" />
          {contextChips}
        </div>
        <Skeleton className="ms-auto h-9 w-24" />
      </div>
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
  const router = useRouter()
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
    const qs = migrated.toString()
    router.replace(`${window.location.pathname}${qs ? `?${qs}` : ''}${window.location.hash}`)
  }, [router])
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
  const openSavedView = useCallback(
    (view: SavedView | null) => {
      if (!view) {
        router.replace('/findings')
        return
      }
      const q = new URLSearchParams({ view: view.id })
      if (view.group_by) q.set('group', view.group_by)
      router.replace(`/findings?${q.toString()}`)
    },
    [router]
  )
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
  const [remedContext, setRemedContext] = useState<{
    ids: string[]
    name?: string
    priority?: string
  } | null>(null)
  const { hasPermission } = usePermissions()
  // The gate of POST /findings/import (the API stays authoritative).
  const canImport =
    hasPermission('findings:write') &&
    hasPermission('assets:write') &&
    hasPermission('assets:import')
  // Both are Phase-3 gated modules embedded in this (findings) page: the "Create
  // Jira Ticket" action hits the integrations module, and "Add to remediation"
  // hits the remediation module. Hide + skip-fetch when disabled (fail-open on
  // OSS where no modules are reported).
  const remediationEnabled = useModuleEnabled('remediation')
  const integrationsEnabled = useModuleEnabled('integrations')

  // Statuses hidden from default dashboard view (pentest WIP, not ready for visibility)
  const HIDDEN_STATUSES = useMemo(() => [...FINDINGS_LIST_HIDDEN_STATUSES], [])

  // Build API filters
  // The source catalog is data, not a hardcoded list. The previous inline list
  // had drifted: it omitted cspm, which live findings actually use, so those
  // findings could not be filtered for at all.
  const { data: sourceCatalog } = useFindingSourcesApi()

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
    debouncedSearch,
    sortParam,
  ].join('|')
  // The filter the current page number belongs to. While a new filter waits
  // for its page reset (the effect below), the list already asks page 1:
  // asking the old page first sent the list request twice (research/81).
  const [pagedFilterKey, setPagedFilterKey] = useState(filterKey)
  const filterChanged = pagedFilterKey !== filterKey
  useEffect(() => {
    if (!filterChanged) return
    setPagedFilterKey(filterKey)
    setPage(1)
  }, [filterChanged, filterKey, setPage])

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
    effectiveSeverities,
    statuses,
    sourceFilter,
    priorityClasses,
    kevActive,
    reachableActive,
    branchOnlyActive,
    mineActive,
    slaFilter,
    debouncedSearch,
    HIDDEN_STATUSES,
    pagination,
    filterChanged,
    sortParam,
    savedId,
    lens,
    rawLens,
  ])

  // The state tab counts follow the filter (RFC-048: stats take the list's
  // filter): the same filter under every lens at once (by_state), so a tab's
  // count is the total its list shows.
  const lensStatsFilters = useMemo(() => {
    const { page: _page, per_page: _perPage, sort: _sort, state: _state, ...rest } = apiFilters
    return { ...rest, state: 'all' as const }
  }, [apiFilters])

  // The overview strip is page-level: every finding the caller may see (their
  // data scope applies server-side), whatever the state tab, search or
  // filters. Filter-aware numbers live in the tab counts and the result bar.
  // With no filter set, the overview and tab-count requests are the same URL,
  // so the page loads ONE stats response; neither key holds the state tab, so
  // switching tabs sends no stats request (research/81).
  const overviewStatsFilters = useMemo(
    () => ({ state: 'all' as const, exclude_statuses: HIDDEN_STATUSES }),
    [HIDDEN_STATUSES]
  )
  const {
    data: findingStats,
    isLoading: statsLoading,
    mutate: mutateOverviewStats,
  } = useFindingStatsApi(overviewStatsFilters)
  const { data: lensStats, mutate: mutateLensStats } = useFindingStatsApi(lensStatsFilters)
  const mutateStats = useCallback(
    () => Promise.all([mutateOverviewStats(), mutateLensStats()]),
    [mutateOverviewStats, mutateLensStats]
  )

  // The flat list. The grouped and verification views render their own rows,
  // so the flat page is not fetched while one of them is shown.
  const {
    data: findingsResponse,
    error,
    isLoading: findingsLoading,
    mutate: mutateFindingsList,
  } = useFindingsApi(apiFilters, { keepPreviousData: true, enabled: !groupBy && !verifyView })
  // Every refresh after a change also reloads the grouped view's groups and rows.
  const mutateFindings = useCallback(() => {
    setGroupsReloadKey((k) => k + 1)
    return mutateFindingsList()
  }, [mutateFindingsList])

  // Headline numbers all come from the one overview stats response — no
  // per-number list requests (those pushed a single page load past the
  // per-user read limit). '—' until the api exposes the field (older api).
  const overview = useMemo(() => findingsOverview(findingStats), [findingStats])

  // Initial loading state (only true when we don't have stats yet)
  const isInitialLoading = statsLoading && !findingStats

  // Transform API data to UI format
  const findings = useMemo(() => {
    if (!findingsResponse?.data) return []
    return findingsResponse.data.map(transformApiToUiFinding)
  }, [findingsResponse])

  const selectedCount = selectedFindingIds.length

  const handleRefresh = async () => {
    await Promise.all([mutateFindings(), mutateStats()])
    await invalidateFindingsCache()
    toast.success('Findings refreshed')
  }

  const canServerExport = hasPermission(Permission.FindingsExport)
  const handleExport = (format: string) => {
    // With findings:export the server streams every matching finding (up to
    // 100,000, scoped and audit-logged); without it, the current page only.
    if (canServerExport) {
      const a = document.createElement('a')
      a.href = buildFindingsExportUrl(apiFilters, format === 'JSON' ? 'ndjson' : 'csv')
      a.rel = 'noopener'
      a.click()
      toast.success('Export started')
      return
    }
    if (!findings.length) {
      toast.error('No findings to export')
      return
    }

    if (format === 'CSV') {
      const headers = ['ID', 'Title', 'Severity', 'Status', 'Source', 'Scanner', 'Created At']
      const rows = findings.map((f) => [
        f.id,
        f.title || '',
        f.severity,
        f.status,
        f.source || '',
        f.scanner || '',
        f.createdAt,
      ])
      downloadCsv(buildCsv(headers, rows), `findings-${new Date().toISOString().split('T')[0]}.csv`)
      toast.success('CSV exported successfully')
    } else if (format === 'JSON') {
      const data = findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        source: f.source,
        scanner: f.scanner,
        cve: f.cve,
        createdAt: f.createdAt,
      }))
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `findings-${new Date().toISOString().split('T')[0]}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('JSON exported successfully')
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
    if (findingIds.length === 0 || !userId.trim()) return

    try {
      const response = await csrfFetch('/api/v1/findings/bulk/assign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ finding_ids: findingIds, user_id: userId.trim() }),
      })
      if (!response.ok) throw new Error('Failed to assign findings')
      showBulkResult(
        summarizeBulkResult(
          await response.json().catch(() => undefined),
          findingIds.length,
          'Assigned'
        )
      )
      clearSelection()
      mutateFindings()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to assign findings'))
    }
  }

  const handleBulkStatusChange = async (status: string) => {
    const findingIds = selectedFindingIds
    if (findingIds.length === 0) return

    try {
      const response = await csrfFetch('/api/v1/findings/bulk/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ finding_ids: findingIds, status }),
      })
      if (!response.ok) throw new Error('Failed to update findings')
      showBulkResult(
        summarizeBulkResult(
          await response.json().catch(() => undefined),
          findingIds.length,
          'Updated'
        )
      )
      clearSelection()
      mutateFindings()
      mutateStats()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update findings'))
    }
  }

  const handleRowClick = useCallback((finding: Finding) => {
    setSelectedFinding(finding)
    setDrawerOpen(true)
  }, [])

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
      const response = await csrfFetch(`/api/v1/findings/${findingToDelete.id}`, {
        method: 'DELETE',
        credentials: 'include',
      })

      if (!response.ok) {
        throw new Error('Failed to delete finding')
      }

      toast.success('Finding deleted', {
        description: findingToDelete.title,
      })
      setDeleteDialogOpen(false)
      setFindingToDelete(null)
      mutateFindings()
      mutateStats()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to delete finding'))
    } finally {
      setIsDeleting(false)
    }
  }

  // Open the "remediate findings" dialog, pre-filled from the selection: the name
  // is derived from the finding(s) and the priority from the highest severity, so
  // the mobilise step is one click from where a finding lives.
  const openRemediationFor = useCallback((selected: Finding[]) => {
    if (selected.length === 0) return
    // Most severe selected finding sets the priority; informational-only
    // selections get the lowest priority rather than a medium default.
    const top = highestSeverity(selected.map((f) => f.severity))
    const priority =
      top === 'critical' ? 'urgent' : top === undefined ? 'medium' : top === 'info' ? 'low' : top
    const name =
      selected.length === 1 ? `Fix: ${selected[0].title}` : `Remediate ${selected.length} findings`
    setRemedContext({ ids: selected.map((f) => f.id), name, priority })
  }, [])

  const handleRowAction = useCallback(
    (action: string, finding: Finding) => {
      switch (action) {
        case 'view':
          handleRowClick(finding)
          break
        case 'remediate':
          openRemediationFor([finding])
          break
        case 'copy_id':
          copyToClipboard(finding.id)
          toast.success('Finding ID copied to clipboard')
          break
        case 'copy_link':
          copyToClipboard(`${window.location.origin}/findings/${finding.id}`)
          toast.success('Link copied to clipboard')
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
        default:
          toast.info(`Action: ${action}`, { description: finding.title })
      }
    },
    [handleRowClick, openRemediationFor]
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
            aria-label="Select all"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label="Select row"
            onClick={(e) => e.stopPropagation()}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      },
      {
        accessorKey: 'title',
        enableSorting: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Title" />,
        cell: ({ row }) => {
          // Use hasDataFlow flag from API (populated via subquery in list view)
          // Fall back to checking dataFlow object for detail view compatibility
          const hasDataFlow =
            row.original.hasDataFlow ||
            (row.original.dataFlow &&
              ((row.original.dataFlow.sources?.length ?? 0) > 0 ||
                (row.original.dataFlow.intermediates?.length ?? 0) > 0 ||
                (row.original.dataFlow.sinks?.length ?? 0) > 0))

          return (
            <div
              className="cursor-pointer max-w-[200px] sm:max-w-md"
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
                        KEV
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-xs text-xs">
                      <p className="font-semibold">CISA Known Exploited Vulnerability</p>
                      {row.original.kevDueDate && (
                        <p>Remediate by {new Date(row.original.kevDueDate).toLocaleDateString()}</p>
                      )}
                    </TooltipContent>
                  </Tooltip>
                )}
                {typeof row.original.epssScore === 'number' && row.original.epssScore > 0 && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="inline-flex shrink-0 items-center rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
                        EPSS {formatEpssScore(row.original.epssScore)}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-xs text-xs">
                      Exploit Prediction Scoring System — estimated probability of exploitation in
                      the next 30 days
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
                      Has attack path data
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
        header: ({ column }) => <DataTableColumnHeader column={column} title="Severity" />,
        cell: ({ row }) => <SeverityBadge severity={row.getValue('severity')} />,
        filterFn: (row, id, value) => {
          return value.includes(row.getValue(id))
        },
      },
      {
        accessorKey: 'priorityClass',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Priority" />,
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
        accessorFn: (row) => row.source || '-',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Source" />,
        cell: ({ row }) => (
          <Badge variant="outline" className="text-xs uppercase">
            {row.getValue('source')}
          </Badge>
        ),
      },
      {
        id: 'asset',
        enableSorting: false,
        accessorFn: (row) => row.assets[0]?.name || '-',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Location" />,
        cell: ({ row }) => {
          const asset = row.original.assets[0]
          const name = asset?.name
          if (!name || name === '-') {
            return <span className="text-muted-foreground text-sm">—</span>
          }
          // The transform falls back to the raw asset_id (a UUID) when the API
          // response carries no asset name or file path — showing that verbatim
          // reads as broken data. Detect it (name === the asset id) and render a
          // compact, clickable asset reference instead of the bare UUID.
          if (asset?.id && name === asset.id) {
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
          return (
            <TruncatedText
              value={name}
              label="Location"
              className="max-w-[200px] font-mono text-sm text-muted-foreground"
            />
          )
        },
      },
      {
        accessorKey: 'status',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
        cell: ({ row }) => <FindingStatusBadge status={row.getValue('status')} />,
        filterFn: (row, id, value) => {
          return value.includes(row.getValue(id))
        },
      },
      {
        accessorKey: 'slaStatus',
        enableSorting: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Due / SLA" />,
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
        header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                <Button variant="ghost" className="h-8 w-8 p-0">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => handleRowAction('view', finding)}>
                  <ExternalLink className="me-2 h-4 w-4" />
                  View Details
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleRowAction('assign', finding)}>
                  <UserPlus className="me-2 h-4 w-4" />
                  Assign
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleRowAction('status', finding)}>
                  <CheckCircle className="me-2 h-4 w-4" />
                  Change Status
                </DropdownMenuItem>
                {integrationsEnabled && (
                  <DropdownMenuItem onClick={() => handleRowAction('create_ticket', finding)}>
                    <Ticket className="me-2 h-4 w-4" />
                    Create Jira Ticket
                  </DropdownMenuItem>
                )}
                {hasPermission('findings:remediation:write') && remediationEnabled && (
                  <DropdownMenuItem onClick={() => handleRowAction('remediate', finding)}>
                    <Wrench className="me-2 h-4 w-4" />
                    Add to remediation
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => handleRowAction('copy_id', finding)}>
                  <Copy className="me-2 h-4 w-4" />
                  Copy ID
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => handleRowAction('copy_link', finding)}>
                  <Link2 className="me-2 h-4 w-4" />
                  Copy Link
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-amber-500"
                  onClick={() => handleRowAction('false_positive', finding)}
                >
                  <Flag className="me-2 h-4 w-4" />
                  Mark as False Positive
                </DropdownMenuItem>
                {hasPermission('findings:delete') && (
                  <DropdownMenuItem
                    className="text-red-500"
                    onClick={() => handleRowAction('delete', finding)}
                  >
                    <Trash2 className="me-2 h-4 w-4" />
                    Delete
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )
        },
      },
    ]
    return hasAnyPriority
      ? cols
      : cols.filter((c) => !('accessorKey' in c) || c.accessorKey !== 'priorityClass')
  }, [
    handleRowAction,
    handleRowClick,
    hasPermission,
    hasAnyPriority,
    remediationEnabled,
    integrationsEnabled,
  ])

  // Error state
  if (error) {
    return (
      <>
        <Main>
          <div className="flex flex-col items-center justify-center py-20">
            <AlertCircle className="h-12 w-12 text-destructive mb-4" />
            <h2 className="text-lg font-semibold mb-2">Failed to load findings</h2>
            <p className="text-muted-foreground mb-4">
              {error?.message || 'An unexpected error occurred'}
            </p>
            <Button onClick={() => mutateFindings()}>
              <RefreshCw className="me-2 h-4 w-4" />
              Retry
            </Button>
          </div>
        </Main>
      </>
    )
  }

  // ---- Filter model shared by the facet panel, the chips and the metrics ----
  const setSeverities = (next: string[]) => setSeverityParam(next)
  const toggleIn = (list: string[], value: string) =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value]
  const sameSet = (a: string[], b: string[]) =>
    a.length === b.length && a.every((v) => b.includes(v))

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
    setMineFilter('false')
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
    slaFilter.length +
    sourceFilter.length

  // Each card is a shortcut: it applies exactly the filter it counts (the
  // Open tab plus one facet), shows as active while that filter is the whole
  // view, and clears it on a second click. Its number never moves with the
  // tab or the filters (research/81).
  const onlyFacet = (facet: 'none' | 'critical' | 'high' | 'sla' | 'kev') =>
    !groupBy &&
    !verifyView &&
    activeCount === (facet === 'none' ? 0 : facet === 'sla' ? OVERDUE_SLA.length : 1) &&
    (facet !== 'critical' || sameSet(severities, ['critical'])) &&
    (facet !== 'high' || sameSet(severities, ['high'])) &&
    (facet !== 'sla' || sameSet(slaFilter, OVERDUE_SLA)) &&
    (facet !== 'kev' || kevActive)
  const showOnly = (nextLens: FindingLens, apply?: () => void) => {
    clearAllFilters()
    setGroupParam('')
    setViewParam('')
    setLensParam(nextLens)
    apply?.()
  }
  const openCard = (facet: 'critical' | 'high' | 'sla' | 'kev', apply: () => void) => {
    const on = lens === 'open' && onlyFacet(facet)
    showOnly('open', on ? undefined : apply)
  }

  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: 'Total',
      description: 'Every finding you can see, in every state (the All tab).',
      value: overview.total,
      onClick: () => showOnly(lens === 'all' && onlyFacet('none') ? 'open' : 'all'),
      active: lens === 'all' && onlyFacet('none'),
    },
    {
      key: 'open',
      label: 'Open',
      description: 'Findings that still need work (the Open tab).',
      value: overview.open,
      onClick: () => showOnly('open'),
      active: lens === 'open' && onlyFacet('none'),
    },
    {
      key: 'critical',
      label: 'Critical open',
      description: 'Open findings of critical severity.',
      value: overview.criticalOpen,
      tone: 'danger',
      onClick: () => openCard('critical', () => setSeverities(['critical'])),
      active: lens === 'open' && onlyFacet('critical'),
    },
    {
      key: 'high',
      label: 'High open',
      description: 'Open findings of high severity.',
      value: overview.highOpen,
      onClick: () => openCard('high', () => setSeverities(['high'])),
      active: lens === 'open' && onlyFacet('high'),
    },
    {
      key: 'overdue',
      label: 'Overdue SLA',
      description: "Open findings past the remediation deadline of your organization's SLA policy.",
      value: overview.overdue,
      tone: 'danger',
      onClick: () => openCard('sla', () => setSlaFilter(OVERDUE_SLA)),
      active: lens === 'open' && onlyFacet('sla'),
    },
    {
      key: 'kev',
      label: 'In CISA KEV',
      description:
        'Open findings whose CVE is in the CISA Known Exploited Vulnerabilities catalog.',
      value: overview.kev,
      tone: 'danger',
      onClick: () => openCard('kev', () => setKevFilter('true')),
      active: lens === 'open' && onlyFacet('kev'),
    },
    {
      // The verification queue: fixes claimed by owners, waiting for a
      // verifier to confirm or reject (grouped by CVE).
      key: 'verify',
      label: 'Awaiting verification',
      description: 'Fixes claimed by an owner, waiting for a verifier.',
      value: overview.awaitingVerification,
      onClick: () => setViewParam(verifyView ? '' : 'verify'),
      active: verifyView,
    },
  ]

  const facetPanel = (
    <FacetPanel activeCount={activeCount} onClearAll={clearAllFilters}>
      <FacetToggle
        label="Assigned to me"
        description="Yours, on assets you own, or your team's"
        checked={mineActive}
        onCheckedChange={(v) => setMineFilter(v ? 'true' : 'false')}
      />
      <FacetSection title="Severity" selectedCount={severities.length}>
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
        title="Priority"
        selectedCount={priorityClasses.length + (kevActive ? 1 : 0) + (reachableActive ? 1 : 0)}
      >
        {PRIORITY_OPTIONS.map((o) => (
          <FacetOption
            key={o.value}
            label={
              <>
                {o.value} <span className="text-muted-foreground">· {o.hint}</span>
              </>
            }
            checked={priorityClasses.includes(o.value)}
            onCheckedChange={() => setPriorityParam(toggleIn(priorityClasses, o.value))}
          />
        ))}
        <FacetGroupLabel>Threat signals</FacetGroupLabel>
        <FacetOption
          label="In CISA KEV"
          checked={kevActive}
          onCheckedChange={(v) => setKevFilter(v ? 'true' : 'false')}
        />
        <FacetOption
          label="Reachable"
          checked={reachableActive}
          onCheckedChange={(v) => setReachableFilter(v ? 'true' : 'false')}
        />
      </FacetSection>
      <FacetSection title="Status" selectedCount={statuses.length}>
        {STATUS_GROUPS.map((g) => (
          <div key={g.key}>
            <FacetGroupLabel
              onSelectAll={() => setStatusParam(Array.from(new Set([...statuses, ...g.values])))}
            >
              {g.key === 'pre_publication'
                ? g.label
                : t(`findings.statusCategory.${g.key}`, g.label)}
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
      <FacetSection title="SLA" selectedCount={slaFilter.length} defaultOpen={false}>
        {SLA_OPTIONS.map((v) => (
          <FacetOption
            key={v}
            label={SLA_STATUS_LABELS[v]}
            checked={slaFilter.includes(v)}
            onCheckedChange={() => toggleSla(v)}
          />
        ))}
      </FacetSection>
      <FacetSection
        title="Branch"
        selectedCount={branchOnlyActive ? 1 : 0}
        defaultOpen={branchOnlyActive}
      >
        <FacetOption
          label="Only on a feature branch"
          checked={branchOnlyActive}
          onCheckedChange={(v) => setBranchOnlyFilter(v ? 'true' : 'false')}
        />
      </FacetSection>
      <FacetSection title="Source" selectedCount={sourceFilter.length} defaultOpen={false}>
        {sourceGroups.length === 0 ? (
          <p className="py-1 text-xs text-muted-foreground">No sources yet.</p>
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
  const total = findingsResponse?.total ?? lensStats?.by_state?.[lens] ?? 0

  const filterButtons = (
    <FilterPanelToggle
      open={filtersOpen}
      onToggle={() => setFiltersOpen((o) => !o)}
      onOpenSheet={() => setFilterSheetOpen(true)}
      activeCount={activeCount}
      controlsId="finding-filters"
    />
  )

  const searchBox = (
    <div className="relative min-w-0 flex-1 sm:max-w-sm">
      <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        placeholder="Search title, CVE, rule or location…"
        aria-label="Search findings"
        className="h-9 ps-9"
      />
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
      <SelectTrigger className="h-9 w-auto gap-2 sm:min-w-36" aria-label="Group findings">
        <Layers className="h-4 w-4 text-muted-foreground" />
        <span className="hidden sm:inline">
          <SelectValue />
        </span>
      </SelectTrigger>
      <SelectContent align="end">
        <SelectItem value="none">Group</SelectItem>
        {GROUP_BY_DIMENSIONS.map((d) => (
          <SelectItem key={d} value={d}>
            {GROUP_BY_LABELS[d]}
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
          aria-label="Refresh"
        >
          <RefreshCw
            className={cn('h-4 w-4', (statsLoading || findingsLoading) && 'animate-spin')}
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>Refresh</TooltipContent>
    </Tooltip>
  )

  const exportMenu = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-9">
          <Download className="h-4 w-4 md:me-2" />
          <span className="hidden md:inline">Export</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => handleExport('CSV')}>Export as CSV</DropdownMenuItem>
        <DropdownMenuItem onClick={() => handleExport('JSON')}>Export as JSON</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  // Filters that arrive from elsewhere (an asset, a scan run, a CVE or rule
  // group) are context, not facets: always shown, inline in the toolbar so they
  // never add a row above the table. Each chip removes only its own parameter.
  const removeContextParam = (param: string) =>
    replaceUrlSearch(removeFilterParam(new URLSearchParams(window.location.search), param))
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
  }
  const contextFilterOn = hasFindingContextFilters(contextFilterValues)
  const contextChips = (
    <FindingContextChips {...contextFilterValues} onRemove={removeContextParam} />
  )

  const toolbarStart = (
    <>
      {filterButtons}
      {searchBox}
      {contextChips}
    </>
  )

  const lensControl = (
    <SegmentedLens<FindingLens>
      label="Finding state"
      countNoun="findings"
      value={lens}
      onChange={(next) => setLensParam(next)}
      options={FINDING_LENSES.map((l) => ({ ...l, count: lensStats?.by_state?.[l.value] }))}
    />
  )

  const toolbarEnd = (
    <>
      {lensControl}
      <SavedViewsMenu
        page="findings"
        activeId={savedId}
        modified={savedViewModified}
        groupBy={groupParam}
        onSelect={openSavedView}
      />
      {groupBySelect}
      {refreshButton}
      {exportMenu}
    </>
  )

  // Grouped view: the groups API takes severity / status / source / "mine";
  // say so when a filter it cannot apply is on, rather than silently ignore it.
  const listOnlyFilterOn =
    contextFilterOn ||
    !!searchQuery.trim() ||
    priorityClasses.length > 0 ||
    kevActive ||
    reachableActive ||
    slaFilter.length > 0
  // Phone layout of a finding row (list and grouped views alike).
  const mobileRow = (f: Finding) => (
    <button
      type="button"
      onClick={() => handleRowClick(f)}
      className="flex w-full items-start gap-3 px-3 py-3 text-start transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <SeverityBadge severity={f.severity} className="mt-0.5 shrink-0" />
      <div className="min-w-0 flex-1">
        <p dir="auto" className="line-clamp-2 text-sm font-medium [unicode-bidi:isolate]">
          {toDisplayText(f.title, 500)}
        </p>
        {(f.cve || f.scanner) && (
          <p className="mt-0.5 truncate text-xs text-muted-foreground">
            {f.cve && <span className="font-mono">{f.cve}</span>}
            {f.cve && f.scanner && ' · '}
            {f.scanner}
          </p>
        )}
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          {f.priorityClass && <PriorityClassBadge priorityClass={f.priorityClass} />}
          <FindingStatusBadge status={f.status} />
          {f.branchOnly && <BranchOnlyBadge />}
          {f.isInKev && (
            <Badge variant="destructive" className="h-5 px-1.5 text-[10px]">
              KEV
            </Badge>
          )}
        </div>
      </div>
      <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />
    </button>
  )

  const listOnlyNote = listOnlyFilterOn && (
    <span className="text-xs text-muted-foreground">
      Search, priority, KEV, SLA and the asset, scan, CVE, rule, family, type, component and owner
      filters apply to the ungrouped list.
    </span>
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
          aria-label={`View the findings of ${group.label}`}
        >
          View
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
            Mark fixed
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
    resetSelectionKey: `${selectionEpoch}|${groupParam}|${viewParam}`,
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
          label: 'Findings',
          onSelect: () => router.push('/findings'),
        },
        {
          label: `By ${GROUP_BY_LABELS[drillDim].toLowerCase()}`,
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
        <PageHeader title="Findings" description={drillBreadcrumb}>
          <Button variant="outline" size="sm" asChild>
            <Link href="/findings/approvals">
              <ClipboardList className="h-4 w-4 sm:me-2" />
              <span className="hidden sm:inline">Approvals</span>
            </Link>
          </Button>
          {canImport && (
            <Button
              variant="outline"
              size="sm"
              aria-label="Import results"
              onClick={() => setImportDialogOpen(true)}
            >
              <FileUp className="h-4 w-4 sm:me-2" />
              <span className="hidden sm:inline">Import results</span>
            </Button>
          )}
          {hasPermission('findings:write') && (
            <Button size="sm" aria-label="Add finding" onClick={() => setCreateDialogOpen(true)}>
              <Plus className="h-4 w-4 sm:me-2" />
              <span className="hidden sm:inline">Add finding</span>
            </Button>
          )}
        </PageHeader>

        <>
          <MetricStrip className="mt-5" loading={isInitialLoading} items={metrics} />

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
                aria-label="Finding filters"
                // A self-contained floating card, as tall as the viewport and
                // pinned while the page scrolls: its length no longer depends
                // on the table's, and long filter lists scroll inside it.
                className="flex h-[calc(100svh-7.5rem)] w-64 flex-col rounded-xl border bg-card p-4 shadow-sm"
              >
                {facetPanelScrollable}
              </aside>
            </div>

            <div className="min-w-0 flex-1 space-y-3">
              {verifyView ? (
                <FindingGroupsTable
                  {...groupedProps}
                  dimension="cve_id"
                  statuses="fix_applied"
                  renderGroupActions={verifyActions}
                  toolbarStart={
                    <>
                      <Button variant="ghost" size="sm" onClick={() => setViewParam('')}>
                        <ArrowLeft className="me-2 h-4 w-4" />
                        All findings
                      </Button>
                      <span className="text-sm text-muted-foreground">
                        Fixes awaiting verification, by CVE
                      </span>
                    </>
                  }
                  toolbarEnd={refreshButton}
                  emptyMessage="No fixes awaiting verification"
                  emptyDescription="Fixes that owners mark as applied wait here for a verifier."
                />
              ) : groupBy ? (
                <FindingGroupsTable
                  {...groupedProps}
                  dimension={groupBy}
                  filters={{
                    severities: effectiveSeverities.join(',') || undefined,
                    statuses: statuses.join(',') || undefined,
                    sources: sourceFilter.join(',') || undefined,
                    assignedToMe: mineActive,
                    branchOnly: branchOnlyActive,
                    view: savedId,
                    state: !savedId || rawLens ? lens : undefined,
                  }}
                  renderGroupActions={groupActions}
                  onViewGroup={viewableGroup ? viewGroup : undefined}
                  onGroupsLoaded={(groups) =>
                    setHasUnassignedGroup(groups.some((g) => g.group_key === 'unassigned'))
                  }
                  toolbarStart={
                    <>
                      {filterButtons}
                      {contextChips}
                      {listOnlyNote}
                    </>
                  }
                  toolbarEnd={
                    <>
                      {lensControl}
                      {groupBy === 'owner_id' && hasUnassignedGroup && (
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-9"
                          onClick={() => setAutoAssignOpen(true)}
                        >
                          <UserPlus className="h-4 w-4 sm:me-2" />
                          <span className="hidden sm:inline">Assign to asset owners</span>
                        </Button>
                      )}
                      {groupBySelect}
                      {refreshButton}
                    </>
                  }
                  emptyDescription={
                    activeCount > 0 ? 'Try removing a filter or clearing them all.' : undefined
                  }
                />
              ) : !findingsResponse && findingsLoading ? (
                <FindingsTableSkeleton contextChips={contextChips} />
              ) : (
                <DataTable
                  columns={columns}
                  data={findings}
                  showSearch={false}
                  toolbarStart={toolbarStart}
                  toolbarEnd={toolbarEnd}
                  getRowId={(f) => f.id}
                  manualPagination
                  rowCount={total}
                  pagination={pagination}
                  onPaginationChange={setPagination}
                  pageSizeOptions={PAGE_SIZES}
                  sorting={sorting}
                  onSortingChange={handleSortingChange}
                  onSelectionChange={setSelectedFindings}
                  resetSelectionKey={selectionEpoch}
                  mobileRow={mobileRow}
                  showSelectionCount={false}
                  emptyMessage="No findings match these filters"
                  emptyDescription={
                    activeCount > 0 ? 'Try removing a filter or clearing them all.' : undefined
                  }
                />
              )}
            </div>
          </div>

          <BulkActionBar count={selectedCount} onClear={clearSelection}>
            <AssigneeSelect
              placeholder="Assign to…"

              onChange={(user) => {
                if (user) void handleBulkAssign(user.id)
              }}
            />

            {hasPermission('findings:remediation:write') && remediationEnabled && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => openRemediationFor(selectedFindings)}
              >
                <Wrench className="me-2 h-4 w-4" />
                Remediation task
              </Button>
            )}

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm">
                  <Flag className="me-2 h-4 w-4" />
                  Status
                </Button>
              </DropdownMenuTrigger>

              <DropdownMenuContent side="top" align="center">
                <DropdownMenuItem onClick={() => handleBulkStatusChange('confirmed')}>
                  Confirmed
                </DropdownMenuItem>

                <DropdownMenuItem onClick={() => handleBulkStatusChange('in_progress')}>
                  In Progress
                </DropdownMenuItem>

                {/* Resolving needs findings:verify; the API refuses it otherwise. */}
                {hasPermission(Permission.FindingsVerify) && (
                  <DropdownMenuItem onClick={() => handleBulkStatusChange('resolved')}>
                    Resolved
                  </DropdownMenuItem>
                )}

                {/* false_positive requires the per-finding approval flow, so it is

                    intentionally not offered as a bulk action. */}
              </DropdownMenuContent>
            </DropdownMenu>
          </BulkActionBar>

          <FilterSheet
            open={filterSheetOpen}
            onOpenChange={setFilterSheetOpen}
            title="Finding filters"
            resultLabel={`Show ${total.toLocaleString()} ${total === 1 ? 'finding' : 'findings'}`}
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

      {/* Mounted only while open: the dialog fetches remediation campaigns on
          mount, so keeping it always-mounted would fire that (gated-module)
          request on every Findings page load. */}
      {remedContext && (
        <LinkFindingsToRemediationDialog
          open={!!remedContext}
          onOpenChange={(open) => {
            if (!open) setRemedContext(null)
          }}
          findingIds={remedContext?.ids ?? []}
          suggestedName={remedContext?.name}
          suggestedPriority={remedContext?.priority}
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

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Delete Finding?"
        desc="This will permanently delete this finding. This action cannot be undone."
        confirmText={
          isDeleting ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              Deleting...
            </>
          ) : (
            'Delete'
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
              {findingToDelete.severity.toUpperCase()} severity
              {findingToDelete.scanner && ` · ${findingToDelete.scanner}`}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </>
  )
}
