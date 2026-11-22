'use client'

import type { ColumnDef } from '@tanstack/react-table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { DataTableRowActions, RelativeTime } from '@/features/shared'
import { ExposureThreatPills } from './exposure-enrichment'
import { APPROVE_REQUIRED_REASON } from './exposure-state-actions'
import { ExposureStateBadge } from './exposure-state-badge'
import { PendingDispositionBadge } from './pending-disposition'
import { ExposureSeverityCell, ExposureSummaryLine } from './exposure-summary'
import {
  Check,
  X,
  AlertTriangle,
  RefreshCw,
  Eye,
  Network,
  Server,
  Globe,
  ShieldCheck,
  Cloud,
  Code,
  Plug,
  Key,
  Database,
  Settings,
  HelpCircle,
  PlayCircle,
  Gauge,
} from 'lucide-react'
import { EVENT_TYPE_CONFIG } from '@/lib/api/exposure-types'
import type { ExposureEvent, ExposureEventType } from '@/lib/api/exposure-types'

// Icon mapping for event types
const eventTypeIcons: Record<string, typeof Network> = {
  network: Network,
  service: Server,
  domain: Globe,
  certificate: ShieldCheck,
  cloud: Cloud,
  code: Code,
  api: Plug,
  credential: Key,
  data: Database,
  config: Settings,
  other: HelpCircle,
}

// One source for an event type's category: EVENT_TYPE_CONFIG.
function getEventTypeIcon(eventType: ExposureEventType): typeof Network {
  const category = EVENT_TYPE_CONFIG[eventType]?.category
  return (category && eventTypeIcons[category as keyof typeof eventTypeIcons]) || HelpCircle
}

export const EXPOSURE_EVENT_TYPE_LABELS: Record<ExposureEventType, string> = {
  port_open: 'Port open',
  port_closed: 'Port closed',
  service_detected: 'Service detected',
  service_changed: 'Service changed',
  subdomain_discovered: 'Subdomain discovered',
  subdomain_removed: 'Subdomain removed',
  certificate_expiring: 'Certificate expiring',
  certificate_expired: 'Certificate expired',
  bucket_public: 'Bucket public',
  bucket_private: 'Bucket private',
  repo_public: 'Repository public',
  repo_private: 'Repository private',
  api_exposed: 'API exposed',
  api_removed: 'API removed',
  credential_leaked: 'Credential leaked',
  sensitive_data_exposed: 'Sensitive data exposed',
  misconfiguration: 'Misconfiguration',
  dns_change: 'DNS change',
  ssl_issue: 'TLS issue',
  header_missing: 'Security header missing',
  dangling_cname: 'Dangling CNAME',
  dangling_ns: 'Dangling delegation',
  email_security_weak: 'Weak email security',
  subdomain_takeover: 'Subdomain takeover',
  lookalike_domain: 'Lookalike domain',
  third_party_script_added: 'New third-party script',
  identity_mfa_gap: 'MFA gap',
  identity_stale_principal: 'Stale identity',
  identity_overprivileged: 'Over-privileged identity',
  web_interface_exposed: 'Web interface exposed',
  mcp_server_exposed: 'MCP server exposed',
  mail_server_blocklisted: 'Mail server blocklisted',
  risky_service_exposed: 'Risky service exposed',
  custom: 'Custom',
}

/** The `t()` of useTranslation(), passed in because column builders are not hooks. */
type Translate = (
  key: string,
  fallback?: string,
  params?: Record<string, string | number>
) => string

export interface ExposureColumnHandlers {
  onResolve: (exposure: ExposureEvent) => void
  onAccept: (exposure: ExposureEvent) => void
  onMarkFalsePositive: (exposure: ExposureEvent) => void
  onReactivate: (exposure: ExposureEvent) => void
  onStartProgress?: (exposure: ExposureEvent) => void
  /** Present when the viewer may change severities (findings:severity and exposures triage). */
  onChangeSeverity?: (exposure: ExposureEvent) => void
  onViewDetails: (exposure: ExposureEvent) => void
  /**
   * Whether the user holds findings:approve. Accept risk and False positive
   * need it (api#675); without it they show disabled, with the reason.
   */
  canApprove?: boolean
}

/** Column widths (px) the room sums below are made of. */
const WIDTH = { select: 40, title: 150, severity: 120, state: 148, age: 112, actions: 48 } as const

/** The room of a frame showing only the always-on columns, the title at 240 px so it stays readable when a column joins. */
const BASE_ROOM = WIDTH.select + 240 + WIDTH.severity + WIDTH.state + WIDTH.age + WIDTH.actions

/**
 * The table-frame width (px) under which a column steps aside (it stays
 * under Display > Columns): the source first, then the signals, then the
 * summary. The exposure, its severity, its state and its age always show.
 * Each value is the running sum of the widths shown at it plus a margin, so
 * a frame never scrolls sideways with the row menu cut.
 */
const EXPOSURE_HIDE_BELOW = {
  summary: BASE_ROOM + 200 + 8,
  signals: BASE_ROOM + 200 + 176 + 8,
  source: BASE_ROOM + 200 + 176 + 120 + 8,
} as const

/**
 * Columns for the exposure list, rendered by the shared DataTable (the
 * checkbox column is the table's own). One line per row. The table
 * is server-paginated and the exposures API takes no sort parameter, so no
 * column is sortable (a header that reordered only the rows on screen would
 * mislead).
 */
/**
 * The plain-words name of an event type in the reader's language. A type this
 * build does not know yet (the server may add one) falls back to its id with
 * the underscores read as spaces.
 */
export function exposureEventTypeLabel(t: Translate, type: string): string {
  const known = (EXPOSURE_EVENT_TYPE_LABELS as Record<string, string | undefined>)[type]
  const fallback = known ?? type.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())
  return t(`exposures.eventType.${type}`, fallback)
}

export function getExposureColumns(
  handlers: ExposureColumnHandlers,
  t: Translate
): ColumnDef<ExposureEvent>[] {
  const eventTypeLabel = (type: ExposureEventType) =>
    t(`exposures.eventType.${type}`, EXPOSURE_EVENT_TYPE_LABELS[type])
  return [
    {
      // The row's identity: frozen at the start while the table scrolls sideways.
      accessorKey: 'title',
      header: t('exposures.table.exposure', 'Exposure'),
      meta: {
        kind: 'name',
        pin: 'start',
        minWidth: WIDTH.title,
        label: t('exposures.table.exposure', 'Exposure'),
      },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => {
        const exposure = row.original
        const Icon = getEventTypeIcon(exposure.event_type)
        return (
          <div className="flex min-w-0 items-center gap-2.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="shrink-0 text-muted-foreground">
                  <Icon className="h-4 w-4" aria-hidden />
                  <span className="sr-only">{eventTypeLabel(exposure.event_type)}</span>
                </span>
              </TooltipTrigger>
              <TooltipContent>{eventTypeLabel(exposure.event_type)}</TooltipContent>
            </Tooltip>
            <span className="min-w-0 truncate font-medium" title={exposure.title}>
              {exposure.title}
            </span>
          </div>
        )
      },
    },
    {
      id: 'summary',
      header: t('exposures.table.summary', 'Summary'),
      meta: {
        kind: 'text',
        minWidth: 200,
        maxWidth: 420,
        hideBelow: EXPOSURE_HIDE_BELOW.summary,
        label: t('exposures.table.summary', 'Summary'),
      },
      enableSorting: false,
      cell: ({ row }) => <ExposureSummaryLine exposure={row.original} inline />,
    },
    {
      id: 'signals',
      header: t('exposures.table.signals', 'Signals'),
      meta: {
        kind: 'signals',
        width: 176,
        hideBelow: EXPOSURE_HIDE_BELOW.signals,
        label: t('exposures.table.signals', 'Signals'),
      },
      enableSorting: false,
      cell: ({ row }) => (
        <ExposureThreatPills exposure={row.original} className="flex-nowrap overflow-hidden" />
      ),
    },
    {
      accessorKey: 'severity',
      header: t('exposures.table.severity', 'Severity'),
      meta: {
        kind: 'severity',
        width: WIDTH.severity,
        label: t('exposures.table.severity', 'Severity'),
      },
      enableSorting: false,
      cell: ({ row }) => <ExposureSeverityCell exposure={row.original} inline />,
    },
    {
      accessorKey: 'state',
      header: t('exposures.table.state', 'State'),
      meta: { kind: 'status', width: WIDTH.state, label: t('exposures.table.state', 'State') },
      enableSorting: false,
      cell: ({ row }) => {
        return (
          <div className="flex items-center gap-1 overflow-hidden whitespace-nowrap">
            <ExposureStateBadge state={row.original.state} />
            <PendingDispositionBadge exposure={row.original} />
          </div>
        )
      },
    },
    {
      accessorKey: 'source',
      header: t('exposures.table.source', 'Source'),
      meta: {
        kind: 'text',
        width: 120,
        hideBelow: EXPOSURE_HIDE_BELOW.source,
        label: t('exposures.table.source', 'Source'),
      },
      enableSorting: false,
      cell: ({ row }) => (
        <span className="block truncate text-muted-foreground" title={row.original.source}>
          {row.original.source}
        </span>
      ),
    },
    {
      accessorKey: 'first_seen_at',
      header: t('exposures.table.firstSeen', 'First seen'),
      meta: {
        kind: 'datetime-recent',
        width: WIDTH.age,
        label: t('exposures.table.firstSeen', 'First seen'),
      },
      enableSorting: false,
      cell: ({ row }) => (
        <RelativeTime date={row.original.first_seen_at} className="whitespace-nowrap" />
      ),
    },
    {
      id: 'actions',
      meta: { kind: 'actions' },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => <ExposureRowMenu exposure={row.original} handlers={handlers} />,
    },
  ]
}

/**
 * The row menu of an exposure: the table row and the phone card draw the
 * same one. Items that need findings:approve stay, disabled, with the reason.
 */
export function ExposureRowMenu({
  exposure,
  handlers,
}: {
  exposure: ExposureEvent
  handlers: ExposureColumnHandlers
}) {
  const { t } = useTranslation()
  return (
    <div onClick={(e) => e.stopPropagation()}>
      <DataTableRowActions
        title={exposure.title}
        label={t('common.rowActions.actionsFor', 'Actions for {name}', {
          name: exposure.title,
        })}
        actions={[
          {
            label: t('exposures.table.viewDetails', 'View details'),
            icon: Eye,
            onClick: () => handlers.onViewDetails(exposure),
          },
          ...(exposure.state === 'active' || exposure.state === 'in_progress'
            ? [
                exposure.state === 'active'
                  ? {
                      label: t('exposures.quick.start', 'Start progress'),
                      icon: PlayCircle,
                      onClick: () => handlers.onStartProgress?.(exposure),
                      separatorBefore: true,
                    }
                  : {
                      label: t('exposures.quick.stop', 'Stop progress'),
                      icon: RefreshCw,
                      onClick: () => handlers.onReactivate(exposure),
                      separatorBefore: true,
                    },
                {
                  label: t('exposures.action.resolveButton', 'Mark resolved'),
                  icon: Check,
                  onClick: () => handlers.onResolve(exposure),
                },
                {
                  label: t('exposures.action.acceptButton', 'Accept risk'),
                  icon: AlertTriangle,
                  onClick: () => handlers.onAccept(exposure),
                  disabled: handlers.canApprove === false,
                  disabledReason: APPROVE_REQUIRED_REASON,
                },
                {
                  label: t('exposures.quick.falsePositive', 'False positive'),
                  icon: X,
                  onClick: () => handlers.onMarkFalsePositive(exposure),
                  disabled: handlers.canApprove === false,
                  disabledReason: APPROVE_REQUIRED_REASON,
                },
              ]
            : [
                {
                  label: t('exposures.action.reactivateButton', 'Reactivate'),
                  icon: RefreshCw,
                  onClick: () => handlers.onReactivate(exposure),
                  separatorBefore: true,
                },
              ]),
          ...(handlers.onChangeSeverity
            ? [
                {
                  label: t('exposures.severity.title', 'Change severity'),
                  icon: Gauge,
                  onClick: () => handlers.onChangeSeverity?.(exposure),
                  separatorBefore: true,
                },
              ]
            : []),
        ]}
      />
    </div>
  )
}
