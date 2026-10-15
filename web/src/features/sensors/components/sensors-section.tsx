'use client'

import { useState, useMemo, useCallback, useEffect } from 'react'
import { Plus, Loader2, Search, Download, Trash2, Layers } from 'lucide-react'
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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { useNow } from '@/hooks/use-now'
import { exportToCsv } from '@/hooks/use-csv-export'
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
import { BulkActionBar, ErrorState, FilterSheet, PageHeader } from '@/features/shared'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { CIPipelinesHint } from '@/features/ci-runners/components/ci-pipelines-hint'
import { SensorsEmptyState } from './sensors-empty-state'

import {
  DEFAULT_FLEET_THRESHOLDS,
  stateLabel,
  SENSOR_STATES,
  stateTakesJobs,
  sensorState,
  type FleetThresholds,
} from '../lib/sensor-state'
import { normalizeSensorVersion, sensorSdkStatus, sensorSdkVersion } from '../lib/sensor-version'
import {
  activeFilterCount,
  filterSensors,
  groupSensors,
  NOT_CONNECTED_STATES,
  summarizeFleet,
  type FleetFilters,
  type FleetGroupBy,
  type ReleaseChannel,
  type SensorModeFilter,
  type SensorProtocolFilter,
  SENSOR_POLICY_FILTERS,
  type SensorPolicyFilter,
  versionStatusIn,
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

const PROTOCOLS: SensorProtocolFilter[] = ['v2', 'v1', 'unknown']
const GROUP_LABELS: Record<Exclude<FleetGroupBy, 'none'>, string> = {
  zone: 'sensors.list.groupBy.zone',
  role: 'sensors.list.groupBy.role',
  version: 'sensors.list.groupBy.version',
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
  const { t } = useTranslation()
  if (!updatedAt) return null
  const secs = Math.max(0, Math.round((now - updatedAt) / 1000))
  return (
    <span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:inline-flex">
      <span aria-hidden className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60 motion-reduce:hidden" />
        <span className="relative inline-flex size-2 rounded-full bg-success" />
      </span>
      {secs < 5
        ? t('sensors.list.liveJustNow')
        : t('sensors.list.liveAgo', undefined, { seconds: secs })}
    </span>
  )
}

export function SensorsSection({
  title: titleProp,
  description: descriptionProp,
}: SensorsSectionProps) {
  // Dialog states
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [pairDialogOpen, setPairDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [regenerateKeyDialogOpen, setRegenerateKeyDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [bulkDeleteDialogOpen, setBulkDeleteDialogOpen] = useState(false)
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  // The sensor waiting for a disable confirmation.
  const [pendingDisable, setPendingDisable] = useState<Sensor | null>(null)
  const { t } = useTranslation()
  const title = titleProp ?? t('sensors.list.title')
  const description = descriptionProp ?? t('sensors.list.description')
  const [detailSheetOpen, setDetailSheetOpen] = useState(false)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [zoneCreateOpen, setZoneCreateOpen] = useState(false)
  // The first sensor is installed from the empty page: "Install with an API
  // key" opens the flow in place, and it stays on screen after the sensor
  // exists (the key, the wait, the tool review) until the admin finishes it,
  // instead of swapping in the table.
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
  // The run-style facet; legacy links carried it (and the collector tab) in
  // ?mode=. CI pipelines are not sensors: /sensors?mode=runner redirects to
  // CI/CD (legacy-routes.ts), and ?mode=all|daemon just open this list.
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
  // CI pipelines have their own page; this page only links there.
  const scansEnabled = useModuleEnabled('scans')
  const canReadCI = useHasPermission(Permission.CIRead) && scansEnabled

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
    // A legacy ?mode=ci|standalone|collector becomes the facet it stood for.
    if (modeParam.length) setModeParam([])
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
      products: tenantSensorStats?.products ?? [],
      sdkLatest: normalizeSensorVersion(tenantSensorStats?.sdk_latest_version),
      sdkAdvisories: tenantSensorStats?.sdk_advisories ?? [],
    }),
    [
      tenantSensorStats?.products,
      tenantSensorStats?.sdk_latest_version,
      tenantSensorStats?.sdk_advisories,
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
    () => groupSensors(filteredSensors, groupBy, zones, t),
    [filteredSensors, groupBy, zones, t]
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
              ·{' '}
              {t(
                rows.length === 1 ? 'sensors.list.count.one' : 'sensors.list.count.other',
                undefined,
                {
                  count: rows.length,
                }
              )}
            </span>
            {zoneGap ? (
              <span className="text-destructive">· {t('sensors.list.zoneGap')}</span>
            ) : (
              <span>· {t('sensors.list.onlineCount', undefined, { count: online })}</span>
            )}
            {key === '__none__' && groupBy === 'zone' && (
              <span>· {t('sensors.list.noZoneHint')}</span>
            )}
          </span>
        )
      },
    }
  }, [groupBy, groups, now, thresholds, t])

  const roleCount = scopedSensors.length

  // Handlers
  const handleRefresh = useCallback(async () => {
    await invalidateSensorsCache()
    await mutate()
    toast.success(t('sensors.list.toast.refreshed'))
  }, [mutate, t])

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
      toast.success(t('sensors.list.toast.deleted', undefined, { name: selectedSensor.name }))
      await invalidateSensorsCache()
      setDeleteDialogOpen(false)
      setSelectedSensor(null)
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.list.toast.deleteFailed')))
    }
  }, [selectedSensor, deleteSensorTrigger, t])

  const handleBulkDeleteConfirm = useCallback(async () => {
    if (selectedIds.length === 0) return

    try {
      const results = await bulkDeleteSensorsTrigger(selectedIds)
      const successCount = results?.filter((r) => r.success).length || 0
      const failCount = results?.filter((r) => !r.success).length || 0

      if (failCount === 0) {
        toast.success(t('sensors.list.toast.bulkDeleted', undefined, { count: successCount }))
      } else if (successCount > 0) {
        toast.warning(
          t('sensors.list.toast.bulkPartial', undefined, {
            success: successCount,
            failed: failCount,
          })
        )
      } else {
        toast.error(t('sensors.list.toast.bulkDeleteFailed'))
      }

      await invalidateSensorsCache()
      setBulkDeleteDialogOpen(false)
      clearSelection()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.list.toast.bulkDeleteFailed')))
    }
  }, [selectedIds, bulkDeleteSensorsTrigger, clearSelection, t])

  const handleActivateSensor = useCallback(
    async (sensor: Sensor) => {
      setSelectedSensor(sensor)
      try {
        const updatedSensor = await activateSensorTrigger(sensor.id)
        toast.success(t('sensors.list.toast.enabled', undefined, { name: sensor.name }))
        await invalidateSensorsCache()
        await mutate()
        if (updatedSensor) setSelectedSensor(updatedSensor)
      } catch (err) {
        toast.error(getErrorMessage(err, t('sensors.list.toast.enableFailed')))
      }
    },
    [activateSensorTrigger, mutate, t]
  )

  const handleDeactivateSensor = useCallback(
    async (sensor: Sensor) => {
      setSelectedSensor(sensor)
      try {
        const updatedSensor = await deactivateSensorTrigger(sensor.id)
        toast.success(t('sensors.list.toast.disabled', undefined, { name: sensor.name }))
        setPendingDisable(null)
        await invalidateSensorsCache()
        await mutate()
        if (updatedSensor) setSelectedSensor(updatedSensor)
      } catch (err) {
        toast.error(getErrorMessage(err, t('sensors.list.toast.disableFailed')))
      }
    },
    [deactivateSensorTrigger, mutate, t]
  )

  const requestDeactivateSensor = useCallback((sensor: Sensor) => {
    setDetailSheetOpen(false)
    setPendingDisable(sensor)
  }, [])

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
      toast.success(t('sensors.list.toast.revoked', undefined, { name: selectedSensor.name }))
      await invalidateSensorsCache()
      await mutate()
      setRevokeDialogOpen(false)
      if (updatedSensor) setSelectedSensor(updatedSensor)
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.list.toast.revokeFailed')))
    } finally {
      setIsRevoking(false)
    }
  }, [selectedSensor, revokeSensorTrigger, mutate, t])

  const handleExport = useCallback(() => {
    exportToCsv(
      filteredSensors,
      [
        { header: t('sensors.list.csv.name'), accessor: (s) => s.name },
        {
          header: t('sensors.list.csv.status'),
          accessor: (s) => stateLabel(sensorState(s, now, thresholds), t),
        },
        { header: t('sensors.list.csv.type'), accessor: (s) => s.type },
        { header: t('sensors.list.csv.mode'), accessor: (s) => s.execution_mode },
        {
          header: t('sensors.list.csv.version'),
          accessor: (s) => normalizeSensorVersion(s.version) ?? '',
        },
        {
          header: t('sensors.list.csv.versionStatus'),
          accessor: (s) => versionStatusIn(s, channel),
        },
        { header: t('sensors.list.csv.sdk'), accessor: (s) => s.sdk_name ?? '' },
        { header: t('sensors.list.csv.sdkVersion'), accessor: (s) => sensorSdkVersion(s) ?? '' },
        { header: t('sensors.list.csv.sdkStatus'), accessor: (s) => sensorSdkStatus(s) },
        { header: t('sensors.list.csv.hostname'), accessor: (s) => s.hostname ?? '' },
        { header: t('sensors.list.csv.ip'), accessor: (s) => s.ip_address ?? '' },
        { header: t('sensors.list.csv.currentJobs'), accessor: (s) => s.current_jobs ?? 0 },
        { header: t('sensors.list.csv.maxJobs'), accessor: (s) => s.max_concurrent_jobs },
        { header: t('sensors.list.csv.outbox'), accessor: (s) => s.outbox?.pending_count ?? '' },
        { header: t('sensors.list.csv.keyExpires'), accessor: (s) => s.key_expires_at ?? '' },
        { header: t('sensors.list.csv.tools'), accessor: (s) => dispatchTools(s).join(' ') },
        { header: t('sensors.list.csv.lastHeartbeat'), accessor: (s) => s.last_seen_at ?? '' },
        { header: t('sensors.list.csv.scans'), accessor: (s) => s.total_scans },
        { header: t('sensors.list.csv.findings'), accessor: (s) => s.total_findings },
      ],
      'sensors'
    )
  }, [filteredSensors, now, thresholds, channel, t])

  const toggleAttention = () => setFilters({ ...filters, attention: !filters.attention })
  const notConnectedActive =
    filters.states.length === NOT_CONNECTED_STATES.length &&
    NOT_CONNECTED_STATES.every((st) => filters.states.includes(st))
  const toggleNotConnected = () =>
    setFilters({ ...filters, states: notConnectedActive ? [] : NOT_CONNECTED_STATES })
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
      hasChannel={(channel.products?.length ?? 0) > 0}
      hasProtocolInfo={summary.hasProtocolInfo}
      hasOneShot={scopedSensors.some((s) => s.execution_mode === 'standalone')}
      sdkVersions={tenantSensorStats?.by_sdk_version}
    />
  )

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder={t('sensors.list.search.placeholder')}
          aria-label={t('sensors.list.search.label')}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="h-9 ps-9"
        />
      </div>
      <Select value={groupBy} onValueChange={(v) => setGroupParam(v === 'none' ? '' : v)}>
        <SelectTrigger
          className="h-9 w-auto gap-2 sm:min-w-36"
          aria-label={t('sensors.list.groupBy.label')}
        >
          <Layers className="h-4 w-4 text-muted-foreground" />
          <span className="sr-only sm:not-sr-only">
            <SelectValue />
          </span>
        </SelectTrigger>
        <SelectContent align="end">
          <SelectItem value="none">{t('sensors.list.groupBy.none')}</SelectItem>
          {zones.length > 0 && <SelectItem value="zone">{t(GROUP_LABELS.zone)}</SelectItem>}
          <SelectItem value="role">{t(GROUP_LABELS.role)}</SelectItem>
          <SelectItem value="version">{t(GROUP_LABELS.version)}</SelectItem>
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

  const fleetEmpty = inlineInstall || (!isLoading && !error && scopedSensors.length === 0)

  let body: React.ReactNode
  if (error && !inlineInstall) {
    body = <ErrorState title={t('sensors.list.errorTitle')} error={error} onRetry={handleRefresh} />
  } else if (isLoading && !inlineInstall) {
    body = <TableSkeleton rows={5} />
  } else if (fleetEmpty) {
    // No sensors yet: what a sensor is and how to add one; "Install with an
    // API key" opens the install flow here.
    body = inlineInstall ? (
      <SensorInstallFlow
        title={t('sensors.list.empty.installTitle')}
        onOpen={(s) => {
          setInlineInstall(false)
          handleViewSensor(s)
        }}
        onDone={() => setInlineInstall(false)}
      />
    ) : (
      <SensorsEmptyState
        canPair={canPairSensors}
        canInstallWithKey={canInstallWithKey}
        canReadCI={canReadCI}
        onPair={() => setPairDialogOpen(true)}
        onInstall={() => setInlineInstall(true)}
      />
    )
  } else {
    body = (
      <SensorTable
        sensors={filteredSensors}
        grants={grants}
        onViewSensor={handleViewSensor}
        onEditSensor={handleEditSensor}
        onActivateSensor={handleActivateSensor}
        onDeactivateSensor={requestDeactivateSensor}
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
  const secondsLabel = (s: number) =>
    s % 60 === 0 && s >= 60
      ? t('sensors.list.minutes', undefined, { count: s / 60 })
      : t('sensors.list.seconds', undefined, { count: s })

  return (
    <>
      <PageHeader title={title} description={description}>
        {zonesTab ? (
          <Can permission={Permission.ScanZonesWrite}>
            <Button size="sm" onClick={() => setZoneCreateOpen(true)}>
              <Plus className="h-4 w-4" />
              {t('sensors.list.addZone')}
            </Button>
          </Can>
        ) : (
          // With no sensor yet, the empty state carries these actions.
          !fleetEmpty && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={handleExport}
                disabled={filteredSensors.length === 0}
              >
                <Download className="h-4 w-4" />
                {t('sensors.list.export')}
              </Button>
              <PairSensorButton onClick={() => setPairDialogOpen(true)} />
              {canInstallWithKey && (
                <Button size="sm" onClick={() => setAddDialogOpen(true)}>
                  <Plus className="h-4 w-4" />
                  {t('sensors.list.install')}
                </Button>
              )}
            </>
          )
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
              {t('sensors.list.tab.sensors')} <TabsCount value={isLoading ? null : roleCount} />
            </TabsTrigger>
            <TabsTrigger value="zones">
              {t('sensors.list.tab.zones')} <TabsCount value={zonesData ? zones.length : null} />
            </TabsTrigger>
          </TabsList>
        </Tabs>
      )}

      {zonesTab ? (
        <ScanZonesPanel createOpen={zoneCreateOpen} onCreateOpenChange={setZoneCreateOpen} />
      ) : (
        <>
          {/* The one way across to CI pipelines: a line, never their list. */}
          {!fleetEmpty && <CIPipelinesHint className="mt-4" enabled={canReadCI} />}
          {/* Where else scans can run: the platform's shared scanning, shown
              only when the organization may use it. */}
          <PlatformScanningCard className="mt-4" />
          {!fleetEmpty && (
            <FleetHealthStrip
              className="mt-5"
              loading={isLoading}
              summary={summary}
              channel={channel}
              notConnectedActive={notConnectedActive}
              onToggleNotConnected={toggleNotConnected}
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
                  aria-label={t('sensors.list.filters')}
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
                  {t('sensors.list.legend', undefined, {
                    offlineAfter: secondsLabel(offlineAfter),
                  })}
                </p>
              )}
            </div>
          </div>
        </>
      )}

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title={t('sensors.list.filters')}
        resultLabel={t(
          filteredSensors.length === 1 ? 'sensors.list.show.one' : 'sensors.list.show.other',
          undefined,
          { count: filteredSensors.length }
        )}
      >
        {facetPanel}
      </FilterSheet>

      <Can permission={Permission.SensorsDelete}>
        <BulkActionBar
          count={selectedIds.length}
          onClear={clearSelection}
          noun={t('sensors.list.selected')}
        >
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive"
            onClick={() => setBulkDeleteDialogOpen(true)}
          >
            <Trash2 className="h-4 w-4" />
            {t('confirm.delete', 'Delete')}
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
            onDeactivate={requestDeactivateSensor}
            onRevoke={handleRevokeSensor}
          />
        </>
      )}

      {/* Delete Confirmation: the sensor's key stops working, so type its name. */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.sensor.deleteTitle', 'Delete the sensor {name}?', {
          name: selectedSensor?.name ?? '',
        })}
        desc={t(
          'confirm.sensor.deleteDesc',
          'Its API key stops working at once and it can no longer claim jobs or send results. Findings it reported stay. This cannot be undone.'
        )}
        confirmText={
          isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        destructive
        isLoading={isDeleting}
        typeToConfirm={selectedSensor?.name}
        handleConfirm={handleDeleteConfirm}
      />

      {/* Bulk Delete Confirmation: type the count. */}
      <ConfirmDialog
        open={bulkDeleteDialogOpen}
        onOpenChange={setBulkDeleteDialogOpen}
        title={
          selectedIds.length === 1
            ? t('confirm.sensor.bulkDeleteTitleOne', 'Delete 1 sensor?')
            : t('confirm.sensor.bulkDeleteTitle', 'Delete {count} sensors?', {
                count: selectedIds.length,
              })
        }
        desc={t(
          'confirm.sensor.bulkDeleteDesc',
          'Their API keys stop working at once and they can no longer claim jobs or send results. Findings they reported stay. This cannot be undone.'
        )}
        confirmText={
          isBulkDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        destructive
        isLoading={isBulkDeleting}
        typeToConfirm={String(selectedIds.length)}
        handleConfirm={handleBulkDeleteConfirm}
      />

      {/* Disable: reversible, the sensor stops claiming jobs until enabled. */}
      <ConfirmDialog
        open={pendingDisable !== null}
        onOpenChange={(open) => !open && setPendingDisable(null)}
        destructive
        title={t('confirm.sensor.disableTitle', 'Disable the sensor {name}?', {
          name: pendingDisable?.name ?? '',
        })}
        desc={t(
          'confirm.sensor.disableDesc',
          'It stops claiming new jobs until you enable it again. Its key and history are kept.'
        )}
        confirmText={t('confirm.disable', 'Disable')}
        handleConfirm={() => (pendingDisable ? handleDeactivateSensor(pendingDisable) : undefined)}
      />

      {/* Revoke Confirmation: permanent, so type the name. */}
      <ConfirmDialog
        open={revokeDialogOpen}
        onOpenChange={setRevokeDialogOpen}
        destructive
        title={t('confirm.sensor.revokeTitle', 'Revoke the sensor {name}?', {
          name: selectedSensor?.name ?? '',
        })}
        desc={t(
          'confirm.sensor.revokeDesc',
          'It loses access at once and for good: its key is revoked and it cannot be re-enabled. To use the machine again, enroll a new sensor. This cannot be undone.'
        )}
        confirmText={
          isRevoking ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.revoking', 'Revoking…')}
            </>
          ) : (
            t('confirm.revoke', 'Revoke')
          )
        }
        isLoading={isRevoking}
        typeToConfirm={selectedSensor?.name}
        handleConfirm={handleRevokeConfirm}
      >
        <p className="text-sm text-muted-foreground">
          {t('confirm.sensor.revokeDisableHint', 'For a temporary stop, disable it instead.')}{' '}
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            disabled={isRevoking}
            onClick={() => {
              setRevokeDialogOpen(false)
              if (selectedSensor) setPendingDisable(selectedSensor)
            }}
          >
            {t('confirm.sensor.disableInstead', 'Disable instead')}
          </Button>
        </p>
      </ConfirmDialog>
    </>
  )
}
