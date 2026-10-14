'use client'

import { useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  AlertTriangle,
  CircleAlert,
  History,
  Info,
  KeyRound,
  Loader2,
  Lock,
  Pencil,
  Power,
  PowerOff,
  RefreshCw,
  ShieldOff,
  Terminal,
  Trash2,
} from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DetailCallout,
  DetailChecklist,
  DetailCopyId,
  DetailDisclosure,
  DetailHeader,
  DetailSheet,
  DetailTabs,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
  DetailStat,
  DetailStatGrid,
  EmptyState,
  RelativeTime,
  type DetailCalloutTone,
  type DetailCheck,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useNow } from '@/hooks/use-now'
import type { ScanZone } from '@/lib/api/scan-zone-types'
import {
  useSensor,
  useSensorCommands,
  useSensorHeartbeatHistory,
  SENSOR_REFRESH_MS,
} from '@/lib/api/sensor-hooks'
import type { Sensor, SensorCommand } from '@/lib/api/sensor-types'
import { sensorRoleOf } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { redactUrlQueries } from '@/lib/redact-url'
import { cn } from '@/lib/utils'
import { useToolAvailability } from '@/lib/api/tool-hooks'
import { sensorToolExclusions } from '@/features/tools/lib/availability'

import { SensorRecentActivity } from './sensor-activity'
import type { EntityActivityHandle } from '@/features/activity/components/entity-activity'
import { requestSensorContentRefresh, SensorContentSection } from './sensor-content-section'
import { SensorControlSection, hasHeartbeatHistory } from './sensor-control-section'
import { SensorLocalPolicySection } from './sensor-local-policy-section'
import { SensorPostureSection } from './sensor-posture'
import { SensorGrantSection } from './sensor-grant-section'
import { SensorManifestTab } from './sensor-manifest-tab'
import { SensorToolSettingsSection } from './sensor-tool-settings'
import { SensorSetupTab } from './config-check-list'
import { SensorStateBadge } from './sensor-state-badge'
import {
  ConfigHealthTag,
  SensorPostureTag,
  distinctHostname,
  LEGACY_KEY_EXPLANATION,
  ProtocolTag,
  PROTOCOL_V1_SUNSET,
  PROTOCOL_V2_SENSOR_VERSION,
  SensorKeyCell,
  SensorTag,
  SensorToolList,
  SensorVersionCell,
} from './sensor-cells'
import { SensorInstallSnippets } from './sensor-install-snippets'
import { SENSOR_TYPE_LABELS } from './sensor-type-icon'
import {
  capacityLabel,
  hasReportedTools,
  sensorCapacity,
  sensorToolRows,
} from '../lib/capabilities'
import { configHealthNeedsAttention } from '../lib/config-report'
import { agoShort, exactTime, formatDurationShort, type Tr } from '../lib/format'
import type { ReleaseChannel } from '../lib/fleet'
import { sensorHealthChecks, type HealthCheck, type HealthCheckAction } from '../lib/health-checks'
import {
  sensorHealthIssues,
  worstIssueSeverity,
  type HealthIssue,
  type HealthIssueAction,
  type HealthIssueSeverity,
} from '../lib/health-issues'
import {
  canTakeJobs,
  isOneShotSensor,
  sensorState,
  stateIsHeartbeating,
  stateTakesJobs,
  type FleetThresholds,
} from '../lib/sensor-state'

interface SensorDetailSheetProps {
  sensor: Sensor | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onEdit: (sensor: Sensor) => void
  onRegenerateKey: (sensor: Sensor) => void
  onViewConfig?: (sensor: Sensor) => void
  onDelete: (sensor: Sensor) => void
  onActivate?: (sensor: Sensor) => void
  onDeactivate?: (sensor: Sensor) => void
  onRevoke?: (sensor: Sensor) => void
  /** State ladder thresholds from GET /sensors/stats. */
  thresholds?: FleetThresholds
  /** Release channel from GET /sensors/stats. */
  channel?: ReleaseChannel
  /** Scan zones (for the zone line) and the fleet (to count a zone's sensors). */
  zones?: Pick<ScanZone, 'id' | 'name' | 'ranges' | 'sensor_ids'>[]
  fleet?: Sensor[]
}

// Activity is not a tab: the Overview's activity summary opens the shared
// ActivityPanel (web/docs/ui/activity-panel.md).
type DrawerTab = 'setup' | 'overview' | 'jobs' | 'manifest' | 'tools' | 'config'

/**
 * The drawer's tabs. Setup & health only on APIs that report config health
 * (the field is present, null before the first report); first, and the tab
 * the drawer opens on, when the setup needs someone.
 */
function drawerTabs(sensor: Pick<Sensor, 'config_health'>, t: Tr): DetailTab<DrawerTab>[] {
  const tabs: DetailTab<DrawerTab>[] = [
    { value: 'overview', label: t('sensors.detail.tab.overview', 'Overview') },
    { value: 'jobs', label: t('sensors.detail.tab.jobs', 'Jobs') },
    { value: 'manifest', label: t('sensors.detail.tab.manifest', 'Manifest') },
    { value: 'config', label: t('sensors.detail.tab.config', 'Config') },
  ]
  const setup: DetailTab<DrawerTab> = {
    value: 'setup',
    label: t('sensors.detail.tab.setup', 'Setup & health'),
  }
  if (sensor.config_health === undefined) return tabs
  if (configHealthNeedsAttention(sensor.config_health)) return [setup, ...tabs]
  return [...tabs, setup]
}

function initialTab(sensor: Pick<Sensor, 'config_health'>): DrawerTab {
  return configHealthNeedsAttention(sensor.config_health) ? 'setup' : 'overview'
}

// ---------------------------------------------------------------------------
// Health: the callout (what is wrong) and the full checklist behind a toggle
// ---------------------------------------------------------------------------

const ACTION_LABEL: Record<HealthIssueAction, { key: string; en: string }> = {
  rotate_key: { key: 'sensors.detail.action.rotate_key', en: 'Rotate key' },
  install: { key: 'sensors.detail.action.install', en: 'Install command' },
  edit: { key: 'sensors.detail.action.edit', en: 'Edit sensor' },
  zones: { key: 'sensors.detail.action.zones', en: 'Zones' },
  refresh_content: { key: 'sensors.detail.action.refresh_content', en: 'Refresh content' },
}

const CALLOUT: Record<HealthIssueSeverity, { tone: DetailCalloutTone; icon: typeof Info }> = {
  critical: { tone: 'destructive', icon: CircleAlert },
  warning: { tone: 'warning', icon: AlertTriangle },
  info: { tone: 'info', icon: Info },
}

/**
 * A sensor health check as a checklist row. Key rotation and editing are
 * admin actions; reading the install command and the zones are not.
 */
function toDetailCheck(
  c: HealthCheck,
  canManage: boolean,
  onAction: (action: HealthCheckAction) => void,
  t: Tr
): DetailCheck {
  const showAction = !!c.action && (c.action === 'install' || c.action === 'zones' || canManage)
  return {
    key: c.key,
    status: c.status,
    label: c.label,
    text: c.text,
    aside: c.aside,
    action:
      showAction && c.action ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 px-2 text-xs"
          onClick={() => onAction(c.action as HealthCheckAction)}
        >
          {t(ACTION_LABEL[c.action].key, ACTION_LABEL[c.action].en)}
        </Button>
      ) : undefined,
  }
}

/** "Show error": the raw error a sensor reported, folded away. */
function RawError({ error }: { error: string }) {
  const { t } = useTranslation()
  return (
    <DetailDisclosure
      summary={t('sensors.detail.showError', 'Show the error')}
      className="mt-1 text-xs"
    >
      <p className="mt-1 rounded-md bg-background/60 p-2 font-mono break-all text-foreground">
        {redactUrlQueries(error)}
      </p>
    </DetailDisclosure>
  )
}

function IssueBody({ issue }: { issue: HealthIssue }) {
  const { t } = useTranslation()
  return (
    <>
      <span className="block">
        {issue.text}
        {issue.since && (
          <>
            {' '}
            <span className="whitespace-nowrap">
              {t('sensors.detail.since', 'Since')}{' '}
              <RelativeTime date={issue.since} className="text-inherit" />.
            </span>
          </>
        )}
      </span>
      {issue.error && <RawError error={issue.error} />}
    </>
  )
}

/**
 * What is wrong with the sensor, why, and the fix, right under the header.
 * Nothing when all is well; the full checklist is one click away either way.
 */
function HealthSummary({
  sensor,
  issues,
  checks,
  canManage,
  onAction,
  onActivity,
}: {
  sensor: Sensor
  issues: HealthIssue[]
  checks: HealthCheck[]
  canManage: boolean
  onAction: (action: HealthCheckAction) => void
  onActivity: () => void
}) {
  const { t } = useTranslation()
  const [refreshing, setRefreshing] = useState(false)
  const worst = worstIssueSeverity(issues)

  // One button per distinct fix the viewer may use.
  const allowed = (a: HealthIssueAction) =>
    a === 'install' || a === 'zones'
      ? true
      : a === 'refresh_content'
        ? canManage && !!sensor.content_refresh_supported
        : canManage
  const actions = [
    ...new Set(issues.map((i) => i.action).filter((a): a is HealthIssueAction => !!a)),
  ].filter(allowed)

  const run = async (a: HealthIssueAction) => {
    if (a !== 'refresh_content') return onAction(a)
    setRefreshing(true)
    try {
      await requestSensorContentRefresh(sensor, t)
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <div className="space-y-2">
      {worst && (
        <DetailCallout
          label={t('sensors.detail.health', 'Health')}
          tone={CALLOUT[worst].tone}
          icon={CALLOUT[worst].icon}
          title={
            issues.length === 1
              ? issues[0].title
              : t('sensors.detail.problems', '{count} problems need attention', {
                  count: issues.length,
                })
          }
          actions={
            <>
              {actions.map((a, i) => (
                <Button
                  key={a}
                  type="button"
                  size="sm"
                  variant={i === 0 ? 'default' : 'outline'}
                  className="h-7 px-2.5 text-xs"
                  disabled={a === 'refresh_content' && refreshing}
                  onClick={() => void run(a)}
                >
                  {a === 'refresh_content' &&
                    (refreshing ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <RefreshCw className="h-3.5 w-3.5" />
                    ))}
                  {t(ACTION_LABEL[a].key, ACTION_LABEL[a].en)}
                </Button>
              ))}
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-xs"
                onClick={onActivity}
              >
                <History className="h-3.5 w-3.5" />
                {t('sensors.detail.viewActivity', 'View activity')}
              </Button>
            </>
          }
        >
          {issues.length === 1 ? (
            <IssueBody issue={issues[0]} />
          ) : (
            <ul className="mt-1 space-y-2">
              {issues.map((i) => (
                <li key={i.key} data-issue={i.key}>
                  <span className="block font-medium text-foreground">{i.title}</span>
                  <IssueBody issue={i} />
                </li>
              ))}
            </ul>
          )}
        </DetailCallout>
      )}

      <DetailChecklist
        checks={checks.map((c) => toDetailCheck(c, canManage, onAction, t))}
        passIcon={!worst}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Overview: stat strip, tools & capacity, identity
// ---------------------------------------------------------------------------

/** "at 15:09" today, "on 1 Oct" before: a short anchor for a relative time. */
function clockAnchor(ms: number, now: number, t: Tr, bare = false): string {
  const d = new Date(ms)
  const sameDay = new Date(now).toDateString() === d.toDateString()
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  const date = d.toLocaleDateString([], { day: 'numeric', month: 'short' })
  if (bare) return sameDay ? time : date
  return sameDay
    ? t('sensors.detail.clockAt', 'at {time}', { time })
    : t('sensors.detail.clockOn', 'on {date}', { date })
}

/**
 * The headline numbers. A number the sensor has not reported is left out,
 * never shown as zero.
 */
function SensorStats({
  sensor,
  now,
  thresholds,
}: {
  sensor: Sensor
  now: number
  thresholds?: FleetThresholds
}) {
  const { t } = useTranslation()
  const state = sensorState(sensor, now, thresholds)
  const oneShot = isOneShotSensor(sensor)
  const running = stateIsHeartbeating(state)
  const cap = sensorCapacity(sensor)
  const current = sensor.current_jobs ?? 0
  const takesJobs = canTakeJobs(sensor, now, thresholds)
  const started = sensor.started_at ? new Date(sensor.started_at).getTime() : NaN

  return (
    <DetailStatGrid aria-label={t('sensors.detail.keyNumbers', 'Key numbers')}>
      {!oneShot && (
        <DetailStat
          label={t('sensors.detail.jobsRunning', 'Jobs running')}
          value={current}
          unit={`/ ${cap.effective}`}
          meter={{
            value: current,
            max: cap.effective,
            label: t('sensors.detail.slotsInUse', 'Job slots in use'),
          }}
          caption={
            takesJobs
              ? t('sensors.detail.slotsFree', '{count} slots free', {
                  count: Math.max(0, cap.effective - current),
                })
              : t('sensors.detail.notTakingJobs', 'Not taking jobs')
          }
        />
      )}
      {sensor.last_seen_at && (
        <DetailStat
          label={
            oneShot
              ? t('sensors.detail.lastRun', 'Last run')
              : t('sensors.detail.lastHeartbeat', 'Last heartbeat')
          }
          value={agoShort(sensor.last_seen_at, now, t)}
          title={exactTime(sensor.last_seen_at)}
          tone={
            state === 'offline'
              ? 'destructive'
              : state === 'late' || state === 'stale'
                ? 'warning'
                : 'default'
          }
          caption={
            Number.isNaN(new Date(sensor.last_seen_at).getTime())
              ? undefined
              : clockAnchor(new Date(sensor.last_seen_at).getTime(), now, t)
          }
        />
      )}
      {running && !Number.isNaN(started) && (
        <DetailStat
          label={t('sensors.detail.upFor', 'Up for')}
          value={formatDurationShort(Math.max(0, (now - started) / 1000))}
          title={exactTime(sensor.started_at)}
          caption={t('sensors.detail.sinceWhen', 'since {when}', {
            when: clockAnchor(started, now, t, true),
          })}
        />
      )}
      <DetailStat
        label={t('sensors.detail.scansToDate', 'Scans to date')}
        value={sensor.total_scans.toLocaleString()}
        caption={
          sensor.total_findings === 1
            ? t('sensors.detail.findings.one', '{count} finding', {
                count: sensor.total_findings.toLocaleString(),
              })
            : t('sensors.detail.findings.other', '{count} findings', {
                count: sensor.total_findings.toLocaleString(),
              })
        }
      />
    </DetailStatGrid>
  )
}

function ToolsAndCapacity({
  sensor,
  now,
  thresholds,
}: {
  sensor: Sensor
  now: number
  thresholds?: FleetThresholds
}) {
  const { t } = useTranslation()
  const cap = sensorCapacity(sensor)
  const reported = hasReportedTools(sensor)
  // Which installed tools its grant or local policy refuses: the same
  // availability view the Tools page and the scan pickers read.
  const { data: availability } = useToolAvailability()
  const exclusions = useMemo(
    () => sensorToolExclusions(availability?.items, sensor.id),
    [availability, sensor.id]
  )
  const platform = sensor.reported?.os
    ? [sensor.reported.os, sensor.reported.arch].filter(Boolean).join('/')
    : null
  const state = sensorState(sensor, now, thresholds)
  const live = stateTakesJobs(state)
  const load =
    live && (sensor.cpu_percent > 0 || sensor.memory_percent > 0)
      ? { cpu: Math.round(sensor.cpu_percent), mem: Math.round(sensor.memory_percent) }
      : null
  return (
    <DetailSection title={t('sensors.detail.toolsCapacity', 'Tools & capacity')}>
      <div className="space-y-2">
        <SensorToolList rows={sensorToolRows(sensor, exclusions)} />
        <p className="text-xs text-muted-foreground">
          {reported
            ? t(
                'sensors.detail.toolsReported',
                'As the sensor reported. Scans go only to tools it has installed and its grant allows.'
              )
            : t(
                'sensors.detail.toolsNotReported',
                'It has not reported its tools yet, so it gets no scans.'
              )}
        </p>
      </div>
      <DetailFieldGrid>
        <DetailField label={t('sensors.detail.concurrentJobs', 'Concurrent jobs')}>
          <span className="flex flex-col gap-0.5 tabular-nums">
            <span>{t('sensors.detail.atOnce', '{count} at once', { count: cap.effective })}</span>
            <span
              className="text-xs text-muted-foreground"
              title={t(
                'sensors.detail.dispatchHint',
                "Dispatch uses the smallest of what the sensor can run now, its operator's cap and your limit"
              )}
            >
              {cap.reported != null || cap.slots != null
                ? capacityLabel(sensor, t)
                : t('sensors.detail.limitNoReport', 'your limit {limit}; the sensor reports none', {
                    limit: cap.limit,
                  })}
            </span>
          </span>
        </DetailField>
        {(platform || load) && (
          <DetailField label={t('sensors.detail.host', 'Host')}>
            <span className="flex flex-col gap-0.5 tabular-nums">
              <span>
                {platform ?? t('sensors.detail.platformNotReported', 'Platform not reported')}
              </span>
              {load && (
                <span className="text-xs text-muted-foreground">
                  <span className={cn(load.cpu >= 90 && 'text-warning')}>
                    {t('sensors.detail.cpu', 'CPU {pct}%', { pct: load.cpu })}
                  </span>
                  {' · '}
                  <span className={cn(load.mem >= 90 && 'text-warning')}>
                    {t('sensors.detail.memory', 'memory {pct}%', { pct: load.mem })}
                  </span>
                </span>
              )}
            </span>
          </DetailField>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}

function ProtocolValue({ sensor }: { sensor: Sensor }) {
  const { t } = useTranslation()
  const p = sensor.protocol
  if (!p) return null
  const v1 = p.deprecated || p.version < 2
  const badge = (
    <SensorTag tone={v1 ? 'warning' : 'muted'}>
      v{p.version}
      {v1 ? ` · ${t('sensors.protocol.deprecated', 'deprecated')}` : ''}
    </SensorTag>
  )
  return (
    <span className="flex flex-col gap-0.5">
      {p.user_agent ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span
              tabIndex={0}
              className="w-fit rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              aria-label={t('sensors.protocol.label', 'Protocol v{version}, {client}', {
                version: p.version,
                client: p.user_agent,
              })}
            >
              {badge}
            </span>
          </TooltipTrigger>
          <TooltipContent className="font-mono text-xs">{p.user_agent}</TooltipContent>
        </Tooltip>
      ) : (
        badge
      )}
      {v1 && (
        <span className="text-xs text-warning">
          {t('sensors.protocol.upgrade', 'Upgrade to {version} before {date}', {
            version: PROTOCOL_V2_SENSOR_VERSION,
            date: PROTOCOL_V1_SUNSET,
          })}
        </span>
      )}
      <TransportValue protocol={p} />
    </span>
  )
}

/** Bindings a heartbeat reports (api RFC-059). */
const TRANSPORT_BINDINGS = new Set(['grpc', 'https', 'v2'])

/** Fallback reasons a sensor reports (sdk-go pkg/client transport_v3_manager.go). */
const TRANSPORT_REASONS = new Set([
  'forced_by_config',
  'not_key_bound',
  'platform_without_v3',
  'platform_without_grpc',
  'certificates_unavailable',
  'grpc_unreachable',
  'handshake_failed',
  'http2_refused',
  'stream_reset',
  'grpc_unimplemented',
  'grpc_failed',
  'https_binding_unavailable',
  'identity_refused',
  'platform_certificate_refused',
  'platform_unreachable',
])

/**
 * The transport of the last heartbeat and, when it is not gRPC, why, in
 * plain words; the reason code is in the tooltip.
 */
function TransportValue({ protocol }: { protocol: NonNullable<Sensor['protocol']> }) {
  const { t } = useTranslation()
  if (!protocol.binding) return null
  const binding = TRANSPORT_BINDINGS.has(protocol.binding)
    ? t(`sensors.transport.binding.${protocol.binding}`, protocol.binding)
    : protocol.binding
  const reason = protocol.fallback_reason
  return (
    <span className="text-xs text-muted-foreground" data-testid="sensor-transport">
      {t('sensors.transport.label', 'Transport: {binding}', { binding })}
      {reason ? (
        <>
          {' · '}
          <Tooltip>
            <TooltipTrigger asChild>
              <span
                tabIndex={0}
                className="rounded-sm underline decoration-dotted underline-offset-2 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                data-testid="sensor-transport-reason"
              >
                {t(`sensors.transport.reason.${TRANSPORT_REASONS.has(reason) ? reason : 'other'}`)}
              </span>
            </TooltipTrigger>
            <TooltipContent className="font-mono text-xs">
              {t('sensors.transport.code', 'Reason code: {code}', { code: reason })}
            </TooltipContent>
          </Tooltip>
        </>
      ) : null}
    </span>
  )
}

function ConnectionAndIdentity({
  sensor,
  now,
  channel,
  zoneNames,
}: {
  sensor: Sensor
  now: number
  channel?: ReleaseChannel
  zoneNames: string[]
}) {
  const { t } = useTranslation()
  const labels = Object.entries(sensor.labels ?? {})
  const host = distinctHostname(sensor)
  const created = new Date(sensor.created_at)
  return (
    <DetailSection title={t('sensors.detail.connection', 'Connection & identity')}>
      <DetailFieldGrid>
        <DetailField label={t('sensors.detail.f.version', 'Version')}>
          <SensorVersionCell sensor={sensor} channel={channel} />
        </DetailField>
        {sensor.protocol && (
          <DetailField label={t('sensors.detail.f.protocol', 'Protocol')}>
            <ProtocolValue sensor={sensor} />
          </DetailField>
        )}
        <DetailField label={t('sensors.detail.f.apiKey', 'API key')}>
          <span className="flex flex-col gap-0.5">
            <span className="font-mono text-xs">{sensor.api_key_prefix}…</span>
            <span className="text-xs [&>span]:text-xs">
              <SensorKeyCell sensor={sensor} now={now} />
            </span>
            {sensor.legacy_key && (
              <span className="text-xs text-muted-foreground">
                {t('sensors.cells.legacyKeyHelp', LEGACY_KEY_EXPLANATION)}
              </span>
            )}
          </span>
        </DetailField>
        {sensor.ip_address && (
          <DetailField label={t('sensors.detail.f.connectsFrom', 'Connects from')}>
            <span className="tabular-nums">{sensor.ip_address}</span>
          </DetailField>
        )}
        {host && (
          <DetailField label={t('sensors.detail.f.hostName', 'Host name')}>{host}</DetailField>
        )}
        {zoneNames.length > 0 && (
          <DetailField label={t('sensors.detail.f.zone', 'Zone')}>
            {zoneNames.join(', ')}
          </DetailField>
        )}
        <DetailField label={t('sensors.detail.f.created', 'Created')}>
          {Number.isNaN(created.getTime()) ? null : (
            <span title={created.toLocaleString()}>
              {created.toLocaleDateString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
              })}{' '}
              <span className="text-muted-foreground">
                (<RelativeTime date={sensor.created_at} className="text-inherit" />)
              </span>
            </span>
          )}
        </DetailField>
        {labels.length > 0 && (
          <DetailField label={t('sensors.detail.f.labels', 'Labels')} full>
            <span className="flex flex-wrap gap-1">
              {labels.map(([k, v]) => (
                <Badge key={k} variant="secondary" className="font-normal">
                  {k}={String(v)}
                </Badge>
              ))}
            </span>
          </DetailField>
        )}
        {sensor.description && (
          <DetailField label={t('sensors.detail.f.description', 'Description')} full>
            {sensor.description}
          </DetailField>
        )}
        <DetailField label={t('sensors.detail.f.id', 'ID')} full>
          <DetailCopyId id={sensor.id} label={t('sensors.detail.sensorId', 'Sensor ID')} />
        </DetailField>
      </DetailFieldGrid>

      <DetailDisclosure summary={t('sensors.detail.moreDetails', 'More details')}>
        <DetailFieldGrid className="mt-3">
          <DetailField label={t('sensors.detail.f.typeLegacy', 'Type (legacy)')}>
            {t(`sensors.table.type.${sensor.type}`, SENSOR_TYPE_LABELS[sensor.type] ?? sensor.type)}
          </DetailField>
          {sensor.started_at && (
            <DetailField label={t('sensors.detail.f.processStarted', 'Process started')}>
              {exactTime(sensor.started_at)}
            </DetailField>
          )}
          {sensor.last_offline_at && (
            <DetailField label={t('sensors.detail.f.lastOffline', 'Last offline')}>
              <RelativeTime date={sensor.last_offline_at} className="text-foreground" />
            </DetailField>
          )}
          {sensor.sensor_commit && (
            <DetailField label={t('sensors.detail.f.commit', 'Commit')}>
              <span className="font-mono text-xs">{sensor.sensor_commit}</span>
            </DetailField>
          )}
          {sensor.sensor_build_time && (
            <DetailField label={t('sensors.detail.f.built', 'Built')}>
              {exactTime(sensor.sensor_build_time)}
            </DetailField>
          )}
          {sensor.protocol?.user_agent && (
            <DetailField label={t('sensors.detail.f.userAgent', 'User agent')} full>
              <span className="font-mono text-xs break-all">{sensor.protocol.user_agent}</span>
            </DetailField>
          )}
        </DetailFieldGrid>
      </DetailDisclosure>
    </DetailSection>
  )
}

// ---------------------------------------------------------------------------
// Jobs tab
// ---------------------------------------------------------------------------

const JOB_STATUS_TONE: Record<string, string> = {
  completed: 'bg-success/15 text-success',
  failed: 'bg-destructive/15 text-destructive',
  running: 'bg-info/15 text-info',
  acknowledged: 'bg-info/15 text-info',
  pending: 'bg-warning/15 text-warning',
}

function jobTitle(c: SensorCommand): string {
  const p = (c.payload ?? {}) as Record<string, unknown>
  const tool = (p.scanner ?? p.tool ?? p.scanner_type) as string | undefined
  return [c.type.replace(/_/g, ' '), tool].filter(Boolean).join(' · ')
}

function jobTarget(c: SensorCommand): string | null {
  const p = (c.payload ?? {}) as Record<string, unknown>
  const t = p.target ?? (Array.isArray(p.targets) ? (p.targets as unknown[]).join(', ') : null)
  return typeof t === 'string' && t ? t : null
}

/** The jobs dispatched to this sensor (GET /commands?sensor_id=). */
function SensorJobs({ sensor }: { sensor: Sensor }) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.CommandsRead)
  const { data, isLoading, error } = useSensorCommands(sensor.id, canRead)
  if (!canRead) {
    return (
      <EmptyState
        icon={Lock}
        title={t('sensors.detail.jobs.noAccessTitle', "You can't see this sensor's jobs")}
        description={t(
          'sensors.detail.jobs.noAccessBody',
          'Viewing jobs needs the sensor commands permission. Ask an organization admin.'
        )}
        card={false}
      />
    )
  }
  if (isLoading && !data) return <Skeleton className="h-40 w-full" />
  if (error) {
    return (
      <p className="text-sm text-muted-foreground">
        {t('sensors.detail.jobs.loadError', 'Could not load the jobs.')}
      </p>
    )
  }
  const jobs = data?.data ?? []
  const oneShot = isOneShotSensor(sensor)
  const cap = sensorCapacity(sensor)
  const current = sensor.current_jobs ?? 0
  return (
    <div className="space-y-4">
      <DetailStatGrid aria-label={t('sensors.detail.jobs.numbers', 'Job numbers')}>
        {!oneShot && (
          <DetailStat
            label={t('sensors.detail.jobs.running', 'Running')}
            value={current}
            unit={`/ ${cap.effective}`}
            meter={{
              value: current,
              max: cap.effective,
              label: t('sensors.detail.slotsInUse', 'Job slots in use'),
            }}
          />
        )}
        <DetailStat
          label={t('sensors.detail.jobs.scans', 'Scans')}
          value={sensor.total_scans.toLocaleString()}
          caption={t('sensors.detail.jobs.allTime', 'all time')}
        />
        <DetailStat
          label={t('sensors.detail.jobs.findings', 'Findings')}
          value={sensor.total_findings.toLocaleString()}
          caption={t('sensors.detail.jobs.allTime', 'all time')}
        />
      </DetailStatGrid>
      {oneShot && (
        <p className="text-sm text-muted-foreground">
          {t('sensors.detail.jobs.ciNote', 'A CI sensor runs its own scans.')}
        </p>
      )}
      {jobs.length === 0 ? (
        <EmptyState
          icon={Terminal}
          title={t('sensors.detail.jobs.emptyTitle', 'No jobs yet')}
          description={t(
            'sensors.detail.jobs.emptyBody',
            'Scans the platform dispatches to this sensor show up here.'
          )}
          card={false}
        />
      ) : (
        <ul className="divide-y rounded-lg border">
          {jobs.map((c) => {
            const target = jobTarget(c)
            return (
              <li key={c.id} className="space-y-1 px-3 py-2.5 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">{jobTitle(c)}</span>
                  <span
                    className={cn(
                      'shrink-0 rounded-full px-2 py-0.5 text-xs font-medium',
                      JOB_STATUS_TONE[c.status] ?? 'bg-muted text-muted-foreground'
                    )}
                  >
                    {t(`sensors.detail.jobs.status.${c.status}`, c.status)}
                  </span>
                </div>
                {target && (
                  <p className="truncate font-mono text-xs text-muted-foreground">{target}</p>
                )}
                <div className="flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                  <span>
                    {t('sensors.detail.jobs.queued', 'queued')}{' '}
                    <RelativeTime date={c.created_at} className="text-xs" />
                  </span>
                  {c.started_at && c.completed_at && (
                    <span className="tabular-nums">
                      {t('sensors.detail.jobs.took', 'took')}{' '}
                      {formatDurationShort(
                        (new Date(c.completed_at).getTime() - new Date(c.started_at).getTime()) /
                          1000
                      )}
                    </span>
                  )}
                  {c.error_message && <span className="text-destructive">{c.error_message}</span>}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// The drawer
// ---------------------------------------------------------------------------

/**
 * The sensor drawer. Read top to bottom: its state and why (a callout naming
 * each problem with its fix), the headline numbers, what it can do (tools,
 * capacity, scanner content), what it did (recent activity), then how it
 * connects and who it is. Jobs, Activity and the install commands are tabs.
 * It re-reads GET /sensors/{id} every 15s while open. Key and lifecycle
 * actions (rotate, disable, revoke, delete) are admin actions in the ⋯ menu:
 * sensors:write and sensors:delete, held by admins and owners only since
 * api#669; revoke and delete are confirmed by the page.
 */
export function SensorDetailSheet({
  sensor: sensorProp,
  open,
  onOpenChange,
  onEdit,
  onRegenerateKey,
  onDelete,
  onActivate,
  onDeactivate,
  onRevoke,
  thresholds,
  channel,
  zones,
  fleet,
}: SensorDetailSheetProps) {
  const { data: live } = useSensor(open && sensorProp ? sensorProp.id : null, {
    refreshInterval: SENSOR_REFRESH_MS,
  })
  // The Control channel sparkline (RFC-035): the last 24 h of heartbeats.
  const { data: heartbeatHistory } = useSensorHeartbeatHistory(
    open && sensorProp ? sensorProp.id : null
  )
  const now = useNow()
  const router = useRouter()
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const canDelete = useHasPermission(Permission.SensorsDelete)
  const [tab, setTab] = useState<DrawerTab>('overview')
  const activityRef = useRef<EntityActivityHandle>(null)
  const [shownId, setShownId] = useState<string | null>(null)
  if (sensorProp && sensorProp.id !== shownId) {
    // Another sensor: start on its overview, or on its setup when that needs someone.
    setShownId(sensorProp.id)
    setTab(initialTab(sensorProp))
  }
  if (!sensorProp) return null
  const sensor = live && live.id === sensorProp.id ? live : sensorProp
  // Tool settings: owners and administrators only (the API enforces it too).
  const tabs = canWrite
    ? [...drawerTabs(sensor, t), { value: 'tools' as const, label: t('sensors.toolSettings.tab') }]
    : drawerTabs(sensor, t)

  const checks = sensorHealthChecks(
    sensor,
    {
      now,
      thresholds,
      channel: channel ?? {},
      zones,
      fleet,
      protocolV2Version: PROTOCOL_V2_SENSOR_VERSION,
      protocolV1Sunset: PROTOCOL_V1_SUNSET,
    },
    t
  )
  const issues = sensorHealthIssues(sensor, checks, now, thresholds, t)
  const handleAction = (action: HealthCheckAction) => {
    if (action === 'rotate_key') onRegenerateKey(sensor)
    else if (action === 'edit') onEdit(sensor)
    else if (action === 'install') setTab('config')
    else if (action === 'zones') {
      onOpenChange(false)
      router.push('/sensors?tab=zones')
    }
  }

  const oneShot = isOneShotSensor(sensor)
  const role =
    sensorRoleOf(sensor.type) === 'collector'
      ? t('sensors.detail.role.collector', 'Collector')
      : t('sensors.detail.role.scanner', 'Scanner')
  const mode = oneShot
    ? t('sensors.detail.mode.ci', 'CI (one-shot)')
    : t('sensors.detail.mode.longRunning', 'Long-running')
  const zoneNames = (zones ?? []).filter((z) => z.sensor_ids.includes(sensor.id)).map((z) => z.name)
  // The subline: what it is and where it runs. The host name only when it
  // says something the name does not.
  const subline = [
    `${role} · ${mode.toLowerCase()}`,
    distinctHostname(sensor),
    sensor.ip_address ?? null,
    zoneNames.length > 0
      ? t('sensors.detail.zoneLine', 'zone {names}', { names: zoneNames.join(', ') })
      : null,
  ].filter((p): p is string => !!p)

  const menu: DetailMenuItem[] = []
  if (canWrite) {
    menu.push({
      label: t('sensors.detail.action.rotate_key', 'Rotate key'),
      icon: KeyRound,
      onSelect: () => onRegenerateKey(sensor),
    })
    if (sensor.status === 'active' && onDeactivate)
      menu.push({
        label: t('sensors.detail.menu.disable', 'Disable'),
        icon: PowerOff,
        onSelect: () => onDeactivate(sensor),
      })
    if (sensor.status !== 'active' && onActivate)
      menu.push({
        label: t('sensors.detail.menu.enable', 'Enable'),
        icon: Power,
        onSelect: () => onActivate(sensor),
      })
  }
  if (canDelete) {
    if (sensor.status !== 'revoked' && onRevoke)
      menu.push({
        label: t('sensors.detail.menu.revoke', 'Revoke access'),
        icon: ShieldOff,
        destructive: true,
        separatorBefore: true,
        onSelect: () => onRevoke(sensor),
      })
    menu.push({
      label: t('sensors.detail.menu.delete', 'Delete'),
      icon: Trash2,
      destructive: true,
      separatorBefore: !(sensor.status !== 'revoked' && onRevoke),
      onSelect: () => {
        onDelete(sensor)
        onOpenChange(false)
      },
    })
  }

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      panel={tab}
      header={
        <DetailHeader
          title={sensor.name}
          badges={
            <>
              <SensorStateBadge sensor={sensor} now={now} thresholds={thresholds} />
              <ProtocolTag sensor={sensor} />
              <ConfigHealthTag health={sensor.config_health} />
              <SensorPostureTag sensor={sensor} />
            </>
          }
          meta={subline}
          menu={menu}
          onClose={() => onOpenChange(false)}
          actions={
            <>
              {canWrite && (
                <Button size="sm" onClick={() => onEdit(sensor)}>
                  <Pencil className="h-4 w-4" />
                  {t('sensors.detail.edit', 'Edit')}
                </Button>
              )}
              <Button size="sm" variant="outline" onClick={() => setTab('config')}>
                <Terminal className="h-4 w-4" />
                {t('sensors.detail.action.install', 'Install command')}
              </Button>
              {!canWrite && (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <Lock className="h-3 w-3" aria-hidden />
                  {t('sensors.detail.needsAdmin', 'Editing, keys and disabling need an admin')}
                </span>
              )}
            </>
          }
        />
      }
      tabs={<DetailTabs tabs={tabs} value={tab} onValueChange={setTab} />}
    >
      {tab === 'overview' && (
        <div className="space-y-5">
          <HealthSummary
            sensor={sensor}
            issues={issues}
            checks={checks}
            canManage={canWrite}
            onAction={handleAction}
            onActivity={() => activityRef.current?.open()}
          />

          <SensorStats sensor={sensor} now={now} thresholds={thresholds} />

          <DetailSections>
            {(!oneShot || sensorToolRows(sensor).length > 0) && (
              <ToolsAndCapacity sensor={sensor} now={now} thresholds={thresholds} />
            )}
            {(sensor.content?.length ?? 0) > 0 && (
              <SensorContentSection sensor={sensor} now={now} canManage={canWrite} />
            )}
            {(sensor.control || hasHeartbeatHistory(heartbeatHistory)) && (
              <SensorControlSection sensor={sensor} now={now} history={heartbeatHistory} />
            )}
            {sensor.posture && <SensorPostureSection sensor={sensor} />}
            {sensor.local_policy && <SensorLocalPolicySection sensor={sensor} />}
            <SensorGrantSection sensorId={sensor.id} sensorType={sensor.type} />
            <SensorRecentActivity ref={activityRef} sensorId={sensor.id} sensorName={sensor.name} />
            <ConnectionAndIdentity
              sensor={sensor}
              now={now}
              channel={channel}
              zoneNames={zoneNames}
            />
          </DetailSections>
        </div>
      )}

      {tab === 'setup' && <SensorSetupTab sensor={sensor} />}

      {tab === 'jobs' && <SensorJobs sensor={sensor} />}

      {tab === 'manifest' && <SensorManifestTab sensor={sensor} now={now} />}

      {tab === 'tools' && canWrite && <SensorToolSettingsSection sensorId={sensor.id} />}

      {tab === 'config' && (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            {t(
              'sensors.detail.configIntro',
              'Run one of these on the host that should scan. The key is shown only when it is issued, so the commands read it from {env}.',
              { env: '\u0000' }
            )
              .split('\u0000')
              .flatMap((part, i) =>
                i === 0
                  ? [part]
                  : [
                      <span key="env" className="font-mono">
                        OPENCTEM_API_KEY
                      </span>,
                      part,
                    ]
              )}
            {canWrite
              ? ` ${t('sensors.detail.configRotate', 'Rotate the key (⋯ menu) to get a new one.')}`
              : ''}
          </p>
          <SensorInstallSnippets sensorId={sensor.id} />
        </div>
      )}
    </DetailSheet>
  )
}
