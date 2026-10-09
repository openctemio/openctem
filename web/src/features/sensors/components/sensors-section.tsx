'use client'

import { useState, useMemo, useCallback, useEffect } from 'react'
import Link from '@/components/link'
import {
  Plus,
  RadioTower,
  Loader2,
  Search,
  Download,
  Trash2,
  Ban,
  Layers,
  Workflow,
} from 'lucide-react'
import { toast } from 'sonner'

import { ScanZonesPanel } from '@/features/scan-zones'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { useNow } from '@/hooks/use-now'
import { exportToCsv } from '@/hooks/use-csv-export'
import { resetListPage } from '@/hooks/use-list-params'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import { InstallSensorDialog } from './install-sensor-dialog'
import { PairSensorButton, PairSensorDialog } from './pair-sensor-dialog'
import { SensorInstallFlow } from './sensor-install-flow'
import { EditSensorDialog } from './edit-sensor-dialog'
import { RegenerateKeyDialog } from './regenerate-key-dialog'
import { SensorDetailSheet } from './sensor-detail-sheet'
import { FleetContentRefreshButton } from './sensor-content-cells'
import { SensorTable } from './sensor-table'
import { FleetHealthStrip } from './fleet-health-strip'
import { SensorFacetPanel } from './sensor-facet-panel'
import { dispatchTools } from '../lib/capabilities'
import {
  useAllSensors,
  useTenantSensorStats,
  useDeleteSensor,
  useBulkDeleteSensors,
  useActivateSensor,
  useDeactivateSensor,
  useRevokeSensor,
  invalidateSensorsCache,
} from '@/lib/api/sensor-hooks'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { useSensorGrantSummaries } from '@/lib/api/sensor-grant-hooks'
import { useSensorIdentityPolicy } from '@/lib/api/sensor-pairing-hooks'
import type { Sensor, SensorRole, SensorState, SensorVersionStatus } from '@/lib/api/sensor-types'
import { Tabs, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PlatformScanningCard } from '@/features/platform'
import {
  BulkActionBar,
  EmptyState,
  ErrorState,
  FilterSheet,
  PageHeader,
  SegmentedLens,
} from '@/features/shared'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { useFleet } from '@/features/ci-runners/api/use-ci'
import { CIPipelinesPanel } from '@/features/ci-runners/components/ci-pipelines-panel'
import { CICDLinkCard } from '@/features/ci-runners/components/ci-cd-link-card'
import { CIPipelineSheet } from '@/features/ci-runners/components/ci-pipeline-sheet'
import { FleetAllView } from './fleet-all-view'

import {
  DEFAULT_FLEET_THRESHOLDS,
  SENSOR_STATE_META,
  SENSOR_STATES,
  stateTakesJobs,
  sensorState,
  type FleetThresholds,
} from '../lib/sensor-state'
import {
  normalizeSensorVersion,
  sensorSdkStatus,
  sensorSdkVersion,
  sensorVersionStatus,
} from '../lib/sensor-version'
import {
  activeFilterCount,
  filterSensors,
  groupSensors,
  summarizeFleet,
  type FleetFilters,
  type FleetGroupBy,
  type ReleaseChannel,
  type SensorModeFilter,
  type SensorProtocolFilter,
  SENSOR_POLICY_FILTERS,
  type SensorPolicyFilter,
} from '../lib/fleet'

interface SensorsSectionProps {
  /** Page title and description; the section renders the page header. */
  title?: string
  description?: string
}

const ROLES: SensorRole[] = ['scanner', 'collector']
const VERSION_STATUSES: SensorVersionStatus[] = [
  'latest',
  'update_available',
  'unsupported',
  'unknown',
]
const MODES: SensorModeFilter[] = ['daemon', 'ci']

/**
 * The page's Mode (api RFC-051 §10): a sensor row runs as a daemon; a CI
 * pipeline is listed in runner mode. The page opens on the daemons; CI
 * pipelines have their own page (CI/CD integration), linked from here, and
 * stay reachable as the Runner and All modes.
 */
export type FleetPageMode = 'all' | 'daemon' | 'runner'

/**
 * The mode a URL asks for. `?mode=` once held the run-style facet
 * (daemon|ci|standalone) and the old collector tab: those links open the
 * daemon list with the same filter.
 */
export function fleetPageMode(raw: string, canDaemon: boolean, canRunner: boolean): FleetPageMode {
  const allowed = (m: FleetPageMode) =>
    m === 'all' ? canDaemon && canRunner : m === 'daemon' ? canDaemon : canRunner
  const values = raw.split(',').map((v) => v.trim())
  for (const v of values) {
    if ((v === 'all' || v === 'daemon' || v === 'runner') && allowed(v)) return v
  }
  if (values.some((v) => v === 'ci' || v === 'standalone' || v === 'collector') && canDaemon) {
    return 'daemon'
  }
  return canDaemon ? 'daemon' : 'runner'
}
const PROTOCOLS: SensorProtocolFilter[] = ['v2', 'v1', 'unknown']
const GROUP_LABELS: Record<Exclude<FleetGroupBy, 'none'>, string> = {
  zone: 'Zone',
  role: 'Role',
  version: 'Version',
}

/** Old single-value links (?status=, ?tab=scanners, ?mode=collector) keep working. */
function legacyStates(status: string): SensorState[] {
  switch (status) {
    case '':
    case 'all':
      return []
    case 'online':
      return ['online', 'degraded', 'late']
    case 'offline':
      return ['stale', 'offline', 'never_connected']
    case 'error':
      return ['degraded']
    default:
      return (SENSOR_STATES as string[]).includes(status) ? [status as SensorState] : []
  }
}

/** "Live · updated 3s ago": the list refreshes every 15s while the tab is visible. */
function LiveIndicator({ updatedAt, now }: { updatedAt: number | null; now: number }) {
  if (!updatedAt) return null
  const secs = Math.max(0, Math.round((now - updatedAt) / 1000))
  return (
    <span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:inline-flex">
      <span aria-hidden className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60 motion-reduce:hidden" />
        <span className="relative inline-flex size-2 rounded-full bg-success" />
      </span>
      Live · updated {secs < 5 ? 'just now' : `${secs}s ago`}
    </span>
  )
}

export function SensorsSection({
  title = 'Sensors',
  description = 'The scanners and collectors that run inside your networks. CI/CD pipelines have their own page.',
}: SensorsSectionProps) {
  // Dialog states
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [pairDialogOpen, setPairDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [regenerateKeyDialogOpen, setRegenerateKeyDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [bulkDeleteDialogOpen, setBulkDeleteDialogOpen] = useState(false)
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  const [detailSheetOpen, setDetailSheetOpen] = useState(false)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [zoneCreateOpen, setZoneCreateOpen] = useState(false)
  // The first sensor is installed from the empty page: keep that flow on
  // screen after the sensor exists (the key, the wait, the tool review)
  // until the admin finishes it, instead of swapping in the table.
  const [inlineInstall, setInlineInstall] = useState(false)

  // Selected sensor for dialogs. The drawer follows the live list (and re-reads
  // GET /sensors/{id}), so it never shows a snapshot from when it was opened.
  const [selectedSensorSnapshot, setSelectedSensor] = useState<Sensor | null>(null)

  // Filters, search and grouping live in the URL so a view can be shared.
  const [tabParam, setTabParam] = useUrlFilter('tab', '')
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const [roleParam, setRoleParam] = useUrlFilterList('role')
  const [stateParam, setStateParam] = useUrlFilterList('state')
  const [versionParam, setVersionParam] = useUrlFilterList('version')
  // The run-style facet; legacy links carried it in ?mode=.
  const [execParam, setExecParam] = useUrlFilterList('exec')
  const [modeParam, setModeParam] = useUrlFilterList('mode')
  const [protocolParam, setProtocolParam] = useUrlFilterList('protocol')
  const [policyParam, setPolicyParam] = useUrlFilterList('policy')
  // The same name and values as the API's GET /sensors?sdk_version= filter.
  const [sdkVersionParam, setSdkVersionParam] = useUrlFilterList('sdk_version')
  const [attentionParam, setAttentionParam] = useUrlFilter('attention', '')
  const [groupParam, setGroupParam] = useUrlFilter('group', '')
  // Pre-redesign links: ?status=online, ?tab=scanners|collectors, ?mode=collector.
  const [legacyStatus, setLegacyStatus] = useUrlFilter('status', '')

  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const canWriteSensors = useHasPermission(Permission.SensorsWrite)
  const canReadSensors = useHasPermission(Permission.SensorsRead)
  // Grant flags on the list (RFC-052): legacy broad grants and New sensors.
  const { data: grantSummaries } = useSensorGrantSummaries(canReadSensors)
  const grants = useMemo(
    () => new Map((grantSummaries?.data ?? []).map((g) => [g.sensor_id, g])),
    [grantSummaries?.data]
  )
  const canPairSensors = useHasPermission(Permission.SensorsPair)
  // RFC-052 D-4: an organization that requires key-bound identity cannot
  // create a sensor with an API key (the API answers 403), so the key-based
  // install flow gives way to pairing there.
  const { data: identityPolicy } = useSensorIdentityPolicy()
  const bearerKeysAllowed = identityPolicy?.bearer_keys_allowed !== false
  const canInstallWithKey = canWriteSensors && bearerKeysAllowed
  const zonesTab = tabParam === 'zones' && canReadZones
  const canDaemon = useHasPermission(Permission.SensorsRead)
  const scansEnabled = useModuleEnabled('scans')
  const canRunner = useHasPermission(Permission.CIRead) && scansEnabled
  const fleetMode: FleetPageMode = fleetPageMode(modeParam.join(','), canDaemon, canRunner)
  const setFleetMode = useCallback(
    (m: FleetPageMode) => {
      setModeParam(m === fleetPageMode('', canDaemon, canRunner) ? [] : [m])
      resetListPage()
    },
    [setModeParam, canDaemon, canRunner]
  )
  // Header counts for the Mode switch (one row of the fleet read model).
  const { data: fleetCounts } = useFleet({ mode: 'all', perPage: 1 }, { enabled: canRunner })
  const runnerCount = fleetCounts?.counts?.runner
    ? (fleetCounts.counts.runner.total ?? 0) - (fleetCounts.counts.runner.inactive ?? 0)
    : undefined
  const [openPipeline, setOpenPipeline] = useState<string | null>(null)

  const filters = useMemo<FleetFilters>(() => {
    const roles = roleParam.filter((r): r is SensorRole => (ROLES as string[]).includes(r))
    if (roles.length === 0 && tabParam === 'scanners') roles.push('scanner')
    if (roles.length === 0 && (tabParam === 'collectors' || modeParam.includes('collector'))) {
      roles.push('collector')
    }
    const states = stateParam.filter((s): s is SensorState =>
      (SENSOR_STATES as string[]).includes(s)
    )
    const modes = [...execParam, ...modeParam.filter((m) => m === 'ci' || m === 'standalone')]
      .map((m) => (m === 'standalone' ? 'ci' : m))
      .filter((m): m is SensorModeFilter => (MODES as string[]).includes(m))
    return {
      q: searchQuery,
      roles,
      states: states.length ? states : legacyStates(legacyStatus),
      versions: versionParam.filter((v): v is SensorVersionStatus =>
        (VERSION_STATUSES as string[]).includes(v)
      ),
      modes,
      protocols: protocolParam.filter((p): p is SensorProtocolFilter =>
        (PROTOCOLS as string[]).includes(p)
      ),
      policies: policyParam.filter((p): p is SensorPolicyFilter =>
        (SENSOR_POLICY_FILTERS as string[]).includes(p)
      ),
      sdkVersions: sdkVersionParam.filter(Boolean),
      attention: attentionParam === '1',
    }
  }, [
    protocolParam,
    policyParam,
    sdkVersionParam,
    roleParam,
    stateParam,
    versionParam,
    execParam,
    modeParam,
    attentionParam,
    searchQuery,
    tabParam,
    legacyStatus,
  ])

  // Writing any facet drops the legacy single-value params it replaces.
  const clearLegacy = useCallback(() => {
    if (legacyStatus) setLegacyStatus('')
    if (tabParam === 'scanners' || tabParam === 'collectors') setTabParam('')
    // A legacy ?mode=ci|standalone|collector becomes the daemon list plus the facet.
    if (modeParam.some((m) => m !== 'all' && m !== 'daemon' && m !== 'runner')) {
      setModeParam(['daemon'])
    }
  }, [legacyStatus, setLegacyStatus, tabParam, setTabParam, modeParam, setModeParam])

  const setFilters = useCallback(
    (next: FleetFilters) => {
      clearLegacy()
      setRoleParam(next.roles)
      setStateParam(next.states)
      setVersionParam(next.versions)
      setExecParam(next.modes)
      setProtocolParam(next.protocols)
      setPolicyParam(next.policies)
      setSdkVersionParam(next.sdkVersions)
      setAttentionParam(next.attention ? '1' : '')
    },
    [
      clearLegacy,
      setRoleParam,
      setStateParam,
      setVersionParam,
      setExecParam,
      setProtocolParam,
      setPolicyParam,
      setSdkVersionParam,
      setAttentionParam,
    ]
  )

  // Row selection (owned by the table; mirrored here for the bulk-action bar)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => setSelectionEpoch((n) => n + 1), [])

  // The clock the state ladder and "4s ago" read (ticks every 5s).
  const now = useNow()

  // API data: the whole fleet (every page), refreshed every 15s.
  const { data: sensorsData, error, isLoading, mutate } = useAllSensors()
  const sensors: Sensor[] = useMemo(() => sensorsData?.items ?? [], [sensorsData?.items])
  const [updatedAt, setUpdatedAt] = useState<number | null>(null)
  useEffect(() => {
    if (sensorsData) setUpdatedAt(Date.now())
  }, [sensorsData])

  const selectedSensor = useMemo(
    () =>
      selectedSensorSnapshot
        ? (sensors.find((s) => s.id === selectedSensorSnapshot.id) ?? selectedSensorSnapshot)
        : null,
    [sensors, selectedSensorSnapshot]
  )

  // Ladder thresholds and the release channel the API uses.
  const { data: tenantSensorStats } = useTenantSensorStats()
  const thresholds = useMemo<FleetThresholds>(
    () => ({
      onlineWindowSeconds:
        tenantSensorStats?.online_window_seconds ?? DEFAULT_FLEET_THRESHOLDS.onlineWindowSeconds,
      offlineAfterSeconds:
        tenantSensorStats?.offline_after_seconds ?? DEFAULT_FLEET_THRESHOLDS.offlineAfterSeconds,
    }),
    [tenantSensorStats?.online_window_seconds, tenantSensorStats?.offline_after_seconds]
  )
  const channel = useMemo<ReleaseChannel>(
    () => ({
      latest: normalizeSensorVersion(tenantSensorStats?.latest_version),
      min: normalizeSensorVersion(tenantSensorStats?.min_version),
      sdkLatest: normalizeSensorVersion(tenantSensorStats?.sdk_latest_version),
      sdkMin: normalizeSensorVersion(tenantSensorStats?.sdk_min_version),
    }),
    [
      tenantSensorStats?.latest_version,
      tenantSensorStats?.min_version,
      tenantSensorStats?.sdk_latest_version,
      tenantSensorStats?.sdk_min_version,
    ]
  )

  // Zones, for grouping and the coverage metric.
  const { data: zonesData } = useScanZones(canReadZones)
  const zones = useMemo(() => zonesData?.data ?? [], [zonesData?.data])

  // Mutations. Each takes the target sensor's id when triggered: the row
  // handlers below select a sensor and trigger in the same call, so a hook
  // bound to `selectedSensor` would act on the previously selected one.
  const { trigger: deleteSensorTrigger, isMutating: isDeleting } = useDeleteSensor()
  const { trigger: bulkDeleteSensorsTrigger, isMutating: isBulkDeleting } = useBulkDeleteSensors()
  const { trigger: activateSensorTrigger } = useActivateSensor()
  const { trigger: deactivateSensorTrigger } = useDeactivateSensor()
  const { trigger: revokeSensorTrigger } = useRevokeSensor()

  // The tenant's own sensors: the API never lists a platform sensor.
  const scopedSensors = sensors

  const summary = useMemo(
    () => summarizeFleet(scopedSensors, now, thresholds, channel, zones),
    [scopedSensors, now, thresholds, channel, zones]
  )

  const filteredSensors = useMemo(
    () => filterSensors(scopedSensors, filters, now, thresholds, channel),
    [scopedSensors, filters, now, thresholds, channel]
  )

  const groupBy: FleetGroupBy =
    groupParam === 'role' || groupParam === 'version' || (groupParam === 'zone' && zones.length)
      ? (groupParam as FleetGroupBy)
      : 'none'

  const groups = useMemo(
    () => groupSensors(filteredSensors, groupBy, zones),
    [filteredSensors, groupBy, zones]
  )
  const rowGroups = useMemo(() => {
    if (groupBy === 'none') return undefined
    const keyOf = new Map<string, string>()
    for (const g of groups) for (const s of g.sensors) keyOf.set(s.id, g.key)
    const byKey = new Map(groups.map((g) => [g.key, g]))
    return {
      getKey: (s: Sensor) => keyOf.get(s.id) ?? '',
      order: groups.map((g) => g.key),
      renderHeader: (key: string, rows: Sensor[]) => {
        const g = byKey.get(key)
        if (!g) return null
        const online = rows.filter((s) => stateTakesJobs(sensorState(s, now, thresholds))).length
        const zoneGap = g.zone && online === 0
        return (
          <span className="flex flex-wrap items-center gap-x-1.5">
            <span className="font-medium text-foreground">{g.label}</span>
            {g.zone && g.zone.ranges.length > 0 && (
              <span className="font-mono">· {g.zone.ranges.slice(0, 2).join(', ')}</span>
            )}
            <span>
              · {rows.length} {rows.length === 1 ? 'sensor' : 'sensors'}
            </span>
            {zoneGap ? (
              <span className="text-destructive">· no online sensor, scans here will wait</span>
            ) : (
              <span>· {online} online</span>
            )}
            {key === '__none__' && groupBy === 'zone' && (
              <span>· takes jobs that no zone claims</span>
            )}
          </span>
        )
      },
    }
  }, [groupBy, groups, now, thresholds])

  const roleCount = scopedSensors.length

  // Handlers
  const handleRefresh = useCallback(async () => {
    await invalidateSensorsCache()
    await mutate()
    toast.success('Sensors refreshed')
  }, [mutate])

  const handleViewSensor = useCallback((sensor: Sensor) => {
    setSelectedSensor(sensor)
    setDetailSheetOpen(true)
  }, [])

  const handleEditSensor = useCallback((sensor: Sensor) => {
    setSelectedSensor(sensor)
    setDetailSheetOpen(false)
    setEditDialogOpen(true)
  }, [])

  const handleRegenerateKey = useCallback((sensor: Sensor) => {
    setSelectedSensor(sensor)
    setDetailSheetOpen(false)
    setRegenerateKeyDialogOpen(true)
  }, [])

  const handleDeleteClick = useCallback((sensor: Sensor) => {
    setSelectedSensor(sensor)
    setDetailSheetOpen(false)
    setDeleteDialogOpen(true)
  }, [])

  const handleDeleteConfirm = useCallback(async () => {
    if (!selectedSensor) return
    try {
      await deleteSensorTrigger(selectedSensor.id)
      toast.success(`Sensor "${selectedSensor.name}" deleted`)
      await invalidateSensorsCache()
      setDeleteDialogOpen(false)
      setSelectedSensor(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to delete sensor'))
    }
  }, [selectedSensor, deleteSensorTrigger])

  const handleBulkDeleteConfirm = useCallback(async () => {
    if (selectedIds.length === 0) return

    try {
      const results = await bulkDeleteSensorsTrigger(selectedIds)
      const successCount = results?.filter((r) => r.success).length || 0
      const failCount = results?.filter((r) => !r.success).length || 0

      if (failCount === 0) {
        toast.success(`${successCount} sensor(s) deleted successfully`)
      } else if (successCount > 0) {
        toast.warning(`${successCount} deleted, ${failCount} failed`)
      } else {
        toast.error('Failed to delete sensors')
      }

      await invalidateSensorsCache()
      setBulkDeleteDialogOpen(false)
      clearSelection()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to delete sensors'))
    }
  }, [selectedIds, bulkDeleteSensorsTrigger, clearSelection])

  const handleActivateSensor = useCallback(
    async (sensor: Sensor) => {
      setSelectedSensor(sensor)
      try {
        const updatedSensor = await activateSensorTrigger(sensor.id)
        toast.success(`Sensor "${sensor.name}" enabled`)
        await invalidateSensorsCache()
        await mutate()
        if (updatedSensor) setSelectedSensor(updatedSensor)
      } catch (err) {
        toast.error(getErrorMessage(err, 'Failed to enable sensor'))
      }
    },
    [activateSensorTrigger, mutate]
  )

  const handleDeactivateSensor = useCallback(
    async (sensor: Sensor) => {
      setSelectedSensor(sensor)
      try {
        const updatedSensor = await deactivateSensorTrigger(sensor.id)
        toast.success(`Sensor "${sensor.name}" disabled`)
        await invalidateSensorsCache()
        await mutate()
        if (updatedSensor) setSelectedSensor(updatedSensor)
      } catch (err) {
        toast.error(getErrorMessage(err, 'Failed to disable sensor'))
      }
    },
    [deactivateSensorTrigger, mutate]
  )

  const handleRevokeSensor = useCallback((sensor: Sensor) => {
    setSelectedSensor(sensor)
    setDetailSheetOpen(false)
    setRevokeDialogOpen(true)
  }, [])

  const [isRevoking, setIsRevoking] = useState(false)

  const handleRevokeConfirm = useCallback(async () => {
    if (!selectedSensor) return
    setIsRevoking(true)
    try {
      const updatedSensor = await revokeSensorTrigger(selectedSensor.id)
      toast.success(`Sensor "${selectedSensor.name}" access revoked`)
      await invalidateSensorsCache()
      await mutate()
      setRevokeDialogOpen(false)
      if (updatedSensor) setSelectedSensor(updatedSensor)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to revoke sensor'))
    } finally {
      setIsRevoking(false)
    }
  }, [selectedSensor, revokeSensorTrigger, mutate])

  const handleExport = useCallback(() => {
    exportToCsv(
      filteredSensors,
      [
        { header: 'Name', accessor: (s) => s.name },
        {
          header: 'Status',
          accessor: (s) => SENSOR_STATE_META[sensorState(s, now, thresholds)].label,
        },
        { header: 'Type', accessor: (s) => s.type },
        { header: 'Mode', accessor: (s) => s.execution_mode },
        { header: 'Version', accessor: (s) => normalizeSensorVersion(s.version) ?? '' },
        {
          header: 'Version status',
          accessor: (s) => sensorVersionStatus(s, channel.latest, channel.min),
        },
        { header: 'SDK', accessor: (s) => s.sdk_name ?? '' },
        { header: 'SDK version', accessor: (s) => sensorSdkVersion(s) ?? '' },
        { header: 'SDK status', accessor: (s) => sensorSdkStatus(s) },
        { header: 'Hostname', accessor: (s) => s.hostname ?? '' },
        { header: 'IP address', accessor: (s) => s.ip_address ?? '' },
        { header: 'Current jobs', accessor: (s) => s.current_jobs ?? 0 },
        { header: 'Max jobs', accessor: (s) => s.max_concurrent_jobs },
        { header: 'Outbox pending', accessor: (s) => s.outbox?.pending_count ?? '' },
        { header: 'Key expires', accessor: (s) => s.key_expires_at ?? '' },
        { header: 'Tools', accessor: (s) => dispatchTools(s).join(' ') },
        { header: 'Last heartbeat', accessor: (s) => s.last_seen_at ?? '' },
        { header: 'Scans', accessor: (s) => s.total_scans },
        { header: 'Findings', accessor: (s) => s.total_findings },
      ],
      'sensors'
    )
  }, [filteredSensors, now, thresholds, channel])

  const toggleAttention = () => setFilters({ ...filters, attention: !filters.attention })
  const updatesActive =
    filters.versions.length === 2 &&
    filters.versions.includes('update_available') &&
    filters.versions.includes('unsupported')
  const toggleUpdates = () =>
    setFilters({
      ...filters,
      versions: updatesActive ? [] : ['update_available', 'unsupported'],
    })
  const toggleZoneGrouping = () => setGroupParam(groupBy === 'zone' ? '' : 'zone')
  const protocolV1Active = filters.protocols.length === 1 && filters.protocols[0] === 'v1'
  const toggleProtocolV1 = () =>
    setFilters({ ...filters, protocols: protocolV1Active ? [] : ['v1'] })

  const filterCount = activeFilterCount(filters)
  const facetPanel = (
    <SensorFacetPanel
      filters={filters}
      onChange={setFilters}
      activeCount={filterCount}
      hasChannel={!!channel.latest || !!channel.min}
      hasProtocolInfo={summary.hasProtocolInfo}
      sdkVersions={tenantSensorStats?.by_sdk_version}
    />
  )

  const modeOptions = [
    ...(canDaemon && canRunner
      ? [
          {
            value: 'all' as const,
            label: 'All',
            count: runnerCount === undefined ? undefined : scopedSensors.length + runnerCount,
            description: 'Daemons and CI pipelines in one list',
          },
        ]
      : []),
    ...(canDaemon
      ? [
          {
            value: 'daemon' as const,
            label: 'Daemon',
            count: isLoading ? undefined : scopedSensors.length,
            description: 'Sensors that run continuously and take jobs',
          },
        ]
      : []),
    ...(canRunner
      ? [
          {
            value: 'runner' as const,
            label: 'Runner',
            count: runnerCount,
            description: 'CI/CD pipelines: the sensor binary runs inside a CI job',
          },
        ]
      : []),
  ]
  const modeLens =
    modeOptions.length > 1 ? (
      <SegmentedLens<FleetPageMode>
        label="Mode"
        value={fleetMode}
        options={modeOptions}
        onChange={setFleetMode}
        countNoun="sensors"
      />
    ) : null

  const toolbarStart = (
    <>
      {modeLens}
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search name, host, IP, version or tool…"
          aria-label="Search sensors"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="h-9 ps-9"
        />
      </div>
      <Select value={groupBy} onValueChange={(v) => setGroupParam(v === 'none' ? '' : v)}>
        <SelectTrigger className="h-9 w-auto gap-2 sm:min-w-36" aria-label="Group sensors">
          <Layers className="h-4 w-4 text-muted-foreground" />
          <span className="hidden sm:inline">
            <SelectValue />
          </span>
        </SelectTrigger>
        <SelectContent align="end">
          <SelectItem value="none">No grouping</SelectItem>
          {zones.length > 0 && <SelectItem value="zone">{GROUP_LABELS.zone}</SelectItem>}
          <SelectItem value="role">{GROUP_LABELS.role}</SelectItem>
          <SelectItem value="version">{GROUP_LABELS.version}</SelectItem>
        </SelectContent>
      </Select>
    </>
  )

  const toolbarEnd = (
    <>
      <LiveIndicator updatedAt={updatedAt} now={now} />
      <FleetContentRefreshButton sensors={scopedSensors} onDone={handleRefresh} />
      <RefreshButton onClick={handleRefresh} loading={isLoading} />
    </>
  )

  const fleetEmpty =
    fleetMode === 'daemon' &&
    (inlineInstall || (!isLoading && !error && scopedSensors.length === 0))

  let body: React.ReactNode
  if (error && !inlineInstall) {
    body = <ErrorState title="sensors" error={error} onRetry={handleRefresh} />
  } else if (isLoading && !inlineInstall) {
    body = <TableSkeleton rows={5} />
  } else if (fleetEmpty) {
    // No sensors yet: the page is the install flow (admins), or says who can
    // install one (everyone else).
    body = (
      <>
        {modeLens && <div className="mb-4">{modeLens}</div>}
        {canInstallWithKey ? (
          <SensorInstallFlow
            title="Install your first sensor"
            onCreated={() => setInlineInstall(true)}
            onOpen={(s) => {
              setInlineInstall(false)
              handleViewSensor(s)
            }}
            onDone={() => setInlineInstall(false)}
          />
        ) : canPairSensors ? (
          <EmptyState
            icon={RadioTower}
            title="Pair your first sensor"
            description="A sensor runs inside your network, scans what the platform cannot reach and sends the results back over HTTPS. Start it on the host with only the platform URL; it prints a code and a fingerprint to pair it here."
            action={<PairSensorButton onClick={() => setPairDialogOpen(true)} />}
          />
        ) : (
          <EmptyState
            icon={RadioTower}
            title="No sensors yet"
            description="A sensor runs inside your network, scans what the platform cannot reach and sends the results back over HTTPS. An organization admin can install one."
          />
        )}
      </>
    )
  } else {
    body = (
      <SensorTable
        sensors={filteredSensors}
        grants={grants}
        onViewSensor={handleViewSensor}
        onEditSensor={handleEditSensor}
        onActivateSensor={handleActivateSensor}
        onDeactivateSensor={handleDeactivateSensor}
        onDeleteSensor={handleDeleteClick}
        onRegenerateKey={handleRegenerateKey}
        onSelectionChange={(rows) => setSelectedIds(rows.map((a) => a.id))}
        resetSelectionKey={selectionEpoch}
        thresholds={thresholds}
        now={now}
        channel={channel}
        rowGroups={rowGroups}
        filterToggle={{
          open: filtersOpen,
          onToggle: () => setFiltersOpen((o) => !o),
          onOpenSheet: () => setFilterSheetOpen(true),
          activeCount: filterCount,
          controlsId: 'sensor-filters',
        }}
        toolbarStart={toolbarStart}
        toolbarEnd={toolbarEnd}
      />
    )
  }

  const offlineAfter = thresholds.offlineAfterSeconds
  const secondsLabel = (s: number) => (s % 60 === 0 && s >= 60 ? `${s / 60} min` : `${s}s`)

  return (
    <>
      <PageHeader title={title} description={description}>
        {zonesTab ? (
          <Can permission={Permission.ScanZonesWrite}>
            <Button size="sm" onClick={() => setZoneCreateOpen(true)}>
              <Plus className="h-4 w-4" />
              Add zone
            </Button>
          </Can>
        ) : (
          <>
            {fleetMode === 'daemon' && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleExport}
                disabled={filteredSensors.length === 0}
              >
                <Download className="h-4 w-4" />
                Export
              </Button>
            )}
            {fleetMode === 'runner' && (
              <Button asChild variant="outline" size="sm">
                <Link href="/ci-cd?tab=setup">
                  <Workflow className="h-4 w-4" />
                  Connect a CI pipeline
                </Link>
              </Button>
            )}
            {fleetMode !== 'runner' && <PairSensorButton onClick={() => setPairDialogOpen(true)} />}
            {canInstallWithKey && (
              <Button size="sm" onClick={() => setAddDialogOpen(true)}>
                <Plus className="h-4 w-4" />
                Install sensor
              </Button>
            )}
          </>
        )}
      </PageHeader>

      {canReadZones && (
        <Tabs
          value={zonesTab ? 'zones' : 'sensors'}
          onValueChange={(v) => setTabParam(v === 'zones' ? 'zones' : '')}
          className="mt-4"
        >
          <TabsList>
            <TabsTrigger value="sensors">
              Sensors <TabsCount value={isLoading ? null : roleCount} />
            </TabsTrigger>
            <TabsTrigger value="zones">
              Scan zones <TabsCount value={zonesData ? zones.length : null} />
            </TabsTrigger>
          </TabsList>
        </Tabs>
      )}

      {zonesTab ? (
        <ScanZonesPanel createOpen={zoneCreateOpen} onCreateOpenChange={setZoneCreateOpen} />
      ) : fleetMode === 'runner' ? (
        <CIPipelinesPanel toolbarStart={modeLens} />
      ) : fleetMode === 'all' ? (
        <>
          <FleetAllView
            toolbarStart={modeLens}
            onOpenDaemon={(id) => {
              const s = sensors.find((x) => x.id === id)
              if (s) handleViewSensor(s)
            }}
            onOpenRunner={setOpenPipeline}
          />
          <CIPipelineSheet id={openPipeline} onClose={() => setOpenPipeline(null)} />
        </>
      ) : (
        <>
          {canRunner && <CICDLinkCard className="mt-4" count={runnerCount} />}
          {/* Where else scans can run: the platform's shared scanning, shown
              only when the organization may use it. */}
          <PlatformScanningCard className="mt-4" />
          {!fleetEmpty && (
            <FleetHealthStrip
              className="mt-5"
              loading={isLoading}
              summary={summary}
              channel={channel}
              attentionActive={filters.attention}
              onToggleAttention={toggleAttention}
              updatesActive={updatesActive}
              onToggleUpdates={toggleUpdates}
              zoneGroupingActive={groupBy === 'zone'}
              onToggleZoneGrouping={toggleZoneGrouping}
              protocolV1Active={protocolV1Active}
              onToggleProtocolV1={toggleProtocolV1}
            />
          )}

          <div className="mt-5 flex items-start">
            {/* The facet panel, as on Findings: a floating card beside the
                table from lg up, a sheet below. */}
            {!fleetEmpty && !error && (
              <div
                inert={!filtersOpen}
                className={cn(
                  'sticky top-4 hidden shrink-0 overflow-hidden transition-[width,margin-inline-end,opacity] duration-300 ease-in-out motion-reduce:transition-none lg:block',
                  filtersOpen ? 'me-5 w-60 opacity-100' : 'me-0 w-0 opacity-0'
                )}
              >
                <aside
                  id="sensor-filters"
                  aria-label="Sensor filters"
                  className="flex max-h-[calc(100svh-7.5rem)] w-60 flex-col rounded-xl border bg-card p-4 shadow-sm"
                >
                  {facetPanel}
                </aside>
              </div>
            )}
            <div className="min-w-0 flex-1">
              {body}
              {!fleetEmpty && !error && !isLoading && (
                <p className="mt-3 text-xs text-muted-foreground">
                  Each sensor is judged against its own heartbeat interval. Online: its next
                  heartbeat is not yet due · Late: past due, still takes work · Stale: well past
                  due, takes no new work · Offline: over 3 intervals (at least 90s) past due, at
                  most {secondsLabel(offlineAfter)} without a heartbeat · Idle (CI): a CI sensor
                  between runs
                </p>
              )}
            </div>
          </div>
        </>
      )}

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title="Sensor filters"
        resultLabel={`Show ${filteredSensors.length} ${filteredSensors.length === 1 ? 'sensor' : 'sensors'}`}
      >
        {facetPanel}
      </FilterSheet>

      <Can permission={Permission.SensorsDelete}>
        <BulkActionBar count={selectedIds.length} onClear={clearSelection} noun="sensors selected">
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive"
            onClick={() => setBulkDeleteDialogOpen(true)}
          >
            <Trash2 className="h-4 w-4" />
            Delete
          </Button>
        </BulkActionBar>
      </Can>

      {pairDialogOpen && (
        <PairSensorDialog open={pairDialogOpen} onOpenChange={setPairDialogOpen} />
      )}

      {/* Mounted only while open: it loads tools and zones. */}
      {addDialogOpen && (
        <InstallSensorDialog
          open={addDialogOpen}
          onOpenChange={setAddDialogOpen}
          onOpen={(s) => {
            setAddDialogOpen(false)
            handleViewSensor(s)
          }}
        />
      )}

      {selectedSensor && (
        <>
          <EditSensorDialog
            open={editDialogOpen}
            onOpenChange={setEditDialogOpen}
            sensor={selectedSensor}
            onSuccess={() => void mutate()}
            onDeleted={() => setSelectedSensor(null)}
          />

          <RegenerateKeyDialog
            open={regenerateKeyDialogOpen}
            onOpenChange={setRegenerateKeyDialogOpen}
            sensor={selectedSensor}
          />

          <SensorDetailSheet
            sensor={selectedSensor}
            thresholds={thresholds}
            channel={channel}
            zones={zones}
            fleet={scopedSensors}
            open={detailSheetOpen}
            onOpenChange={setDetailSheetOpen}
            onEdit={handleEditSensor}
            onRegenerateKey={handleRegenerateKey}
            onDelete={handleDeleteClick}
            onActivate={handleActivateSensor}
            onDeactivate={handleDeactivateSensor}
            onRevoke={handleRevokeSensor}
          />
        </>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Delete sensor"
        desc={
          <>
            Are you sure you want to delete <strong>{selectedSensor?.name}</strong>? This action
            cannot be undone and will invalidate the sensor&apos;s API key.
          </>
        }
        confirmText="Delete"
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDeleteConfirm}
      />

      {/* Bulk Delete Confirmation */}
      <ConfirmDialog
        open={bulkDeleteDialogOpen}
        onOpenChange={setBulkDeleteDialogOpen}
        title="Delete sensors"
        desc={
          <>
            Are you sure you want to delete <strong>{selectedIds.length}</strong> sensor(s)? This
            action cannot be undone and will invalidate all their API keys.
          </>
        }
        confirmText="Delete all"
        destructive
        isLoading={isBulkDeleting}
        handleConfirm={handleBulkDeleteConfirm}
      />

      {/* Revoke Confirmation */}
      <AlertDialog open={revokeDialogOpen} onOpenChange={setRevokeDialogOpen}>
        <AlertDialogContent className="max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <Ban className="h-5 w-5" />
              Revoke sensor access
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2">
                <p>
                  Permanently revoke access for <strong>{selectedSensor?.name}</strong>?
                </p>
                <div className="rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive">
                  <p className="text-xs font-medium">This is permanent</p>
                  <ul className="mt-1.5 space-y-0.5 text-xs">
                    <li>- Sensor loses access immediately</li>
                    <li>- Cannot be undone</li>
                    <li>- Must create new sensor to restore</li>
                  </ul>
                </div>
                <p className="text-xs text-muted-foreground">
                  Use <strong>Disable</strong> for temporary suspension.
                </p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isRevoking}>Cancel</AlertDialogCancel>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setRevokeDialogOpen(false)
                if (selectedSensor) {
                  handleDeactivateSensor(selectedSensor)
                }
              }}
              disabled={isRevoking}
            >
              Disable
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleRevokeConfirm}
              disabled={isRevoking}
            >
              {isRevoking && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              Revoke
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
