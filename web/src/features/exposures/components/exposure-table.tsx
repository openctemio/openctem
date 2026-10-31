'use client'

import type { ColumnDef } from '@tanstack/react-table'
import { Checkbox } from '@/components/ui/checkbox'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
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
  identity_mfa_gap: 'MFA gap',
  identity_stale_principal: 'Stale identity',
  identity_overprivileged: 'Over-privileged identity',
  web_interface_exposed: 'Web interface exposed',
  mcp_server_exposed: 'MCP server exposed',
  mail_server_blocklisted: 'Mail server blocklisted',
  custom: 'Custom',
}

interface ExposureColumnHandlers {
  onResolve: (exposure: ExposureEvent) => void
  onAccept: (exposure: ExposureEvent) => void
  onMarkFalsePositive: (exposure: ExposureEvent) => void
  onReactivate: (exposure: ExposureEvent) => void
  onStartProgress?: (exposure: ExposureEvent) => void
  /** Present when the viewer may change severities (findings:severity and exposures triage). */
  onChangeSeverity?: (exposure: ExposureEvent) => void
  onViewDetails: (exposure: ExposureEvent) => void
  /** Labels of the row actions this table adds, in the viewer's language. */
  labels?: { startProgress: string; stopProgress: string; changeSeverity: string }
  /**
   * Whether the user holds findings:approve. Accept risk and False positive
   * need it (api#675); without it they show disabled, with the reason.
   */
  canApprove?: boolean
}

/**
 * Columns for the exposure list, rendered by the shared DataTable. The table
 * is server-paginated and the exposures API takes no sort parameter, so no
 * column is sortable (a header that reordered only the rows on screen would
 * mislead).
 */
export function getExposureColumns(handlers: ExposureColumnHandlers): ColumnDef<ExposureEvent>[] {
  return [
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
          aria-label={`Select ${row.original.title}`}
          onClick={(e) => e.stopPropagation()}
        />
      ),
      enableSorting: false,
      enableHiding: false,
    },
    {
      accessorKey: 'title',
      header: 'Exposure',
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => {
        const exposure = row.original
        const Icon = getEventTypeIcon(exposure.event_type)
        return (
          <div className="flex min-w-0 items-start gap-2.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="mt-0.5 shrink-0 text-muted-foreground">
                  <Icon className="h-4 w-4" aria-hidden />
                  <span className="sr-only">{EXPOSURE_EVENT_TYPE_LABELS[exposure.event_type]}</span>
                </span>
              </TooltipTrigger>
              <TooltipContent>{EXPOSURE_EVENT_TYPE_LABELS[exposure.event_type]}</TooltipContent>
            </Tooltip>
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <p className="line-clamp-1 font-medium">{exposure.title}</p>
                <ExposureThreatPills exposure={exposure} />
              </div>
              <ExposureSummaryLine exposure={exposure} />
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      enableSorting: false,
      cell: ({ row }) => <ExposureSeverityCell exposure={row.original} />,
    },
    {
      accessorKey: 'state',
      header: 'State',
      enableSorting: false,
      cell: ({ row }) => {
        return (
          <div className="flex flex-wrap items-center gap-1">
            <ExposureStateBadge state={row.original.state} />
            <PendingDispositionBadge exposure={row.original} />
          </div>
        )
      },
    },
    {
      accessorKey: 'source',
      header: 'Source',
      enableSorting: false,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{row.original.source}</span>
      ),
    },
    {
      accessorKey: 'first_seen_at',
      header: 'First seen',
      enableSorting: false,
      cell: ({ row }) => <RelativeTime date={row.original.first_seen_at} />,
    },
    {
      id: 'actions',
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => {
        const exposure = row.original
        return (
          <div onClick={(e) => e.stopPropagation()}>
            <DataTableRowActions
              actions={[
                {
                  label: 'View details',
                  icon: Eye,
                  onClick: () => handlers.onViewDetails(exposure),
                },
                ...(exposure.state === 'active' || exposure.state === 'in_progress'
                  ? [
                      exposure.state === 'active'
                        ? {
                            label: handlers.labels?.startProgress ?? 'Start progress',
                            icon: PlayCircle,
                            onClick: () => handlers.onStartProgress?.(exposure),
                            separatorBefore: true,
                          }
                        : {
                            label: handlers.labels?.stopProgress ?? 'Stop progress',
                            icon: RefreshCw,
                            onClick: () => handlers.onReactivate(exposure),
                            separatorBefore: true,
                          },
                      {
                        label: 'Mark resolved',
                        icon: Check,
                        onClick: () => handlers.onResolve(exposure),
                      },
                      {
                        label: 'Accept risk',
                        icon: AlertTriangle,
                        onClick: () => handlers.onAccept(exposure),
                        disabled: handlers.canApprove === false,
                        disabledReason: APPROVE_REQUIRED_REASON,
                      },
                      {
                        label: 'False positive',
                        icon: X,
                        onClick: () => handlers.onMarkFalsePositive(exposure),
                        disabled: handlers.canApprove === false,
                        disabledReason: APPROVE_REQUIRED_REASON,
                      },
                    ]
                  : [
                      {
                        label: 'Reactivate',
                        icon: RefreshCw,
                        onClick: () => handlers.onReactivate(exposure),
                        separatorBefore: true,
                      },
                    ]),
                ...(handlers.onChangeSeverity
                  ? [
                      {
                        label: handlers.labels?.changeSeverity ?? 'Change severity',
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
      },
    },
  ]
}
