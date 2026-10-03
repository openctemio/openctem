import type { ColumnDef } from '@tanstack/react-table'
import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import type { Asset } from '@/features/assets'
import {
  cdnName,
  contentType,
  formatTechnology,
  httpStatusCode,
  ipAddresses,
  pageTitle,
  redirectChain,
  redirectTarget,
  responseTimeMs,
  technologies,
  tlsFacts,
  webServer,
} from '@/features/assets/lib/service-facts'
import {
  ChipRow,
  EmptyCell,
  HttpStatusChip,
  OverflowChips,
  TechChips,
  TlsSummary,
  tlsNotCollected,
} from '@/features/assets/components/service-cells'
import { SafeExternalLink } from '@/components/safe-external-link'
import { MonitorSmartphone, ShieldCheck, ShieldX, AlertTriangle, Shield, Zap } from 'lucide-react'

/** "Served over TLS" / "No TLS" / "" (unknown) for the CSV. */
function tlsLabel(asset: Asset): string {
  const k = tlsFacts(asset).kind
  return k === 'cert' || k === 'tls' ? 'Yes' : k === 'none' ? 'No' : ''
}

// Each cell reads the keys ingest stores (status_code, technologies,
// web_server, service.*) as well as the manual form's keys, through
// service-facts. A value nothing recorded is never defaulted: it is an
// empty cell (`—`) in the list and one "Not collected yet" line in the
// drawer (ui-style-contract §7, "Unknown facts").
const columns: ColumnDef<Asset>[] = [
  {
    id: 'http_status',
    header: 'Status',
    cell: ({ row }) => (
      <div className="min-w-0 max-w-[220px] space-y-1">
        <HttpStatusChip
          status={httpStatusCode(row.original)}
          chain={redirectChain(row.original)}
          fallback={pageTitle(row.original) ? null : <EmptyCell />}
        />
        {pageTitle(row.original) && (
          <p className="truncate text-xs text-muted-foreground" title={pageTitle(row.original)}>
            {pageTitle(row.original)}
          </p>
        )}
      </div>
    ),
  },
  {
    id: 'technology',
    header: 'Technologies',
    cell: ({ row }) => (
      <ChipRow className="max-w-[240px]">
        <TechChips technologies={technologies(row.original)} max={2} fallback={<EmptyCell />} />
      </ChipRow>
    ),
  },
  {
    id: 'ssl',
    header: 'TLS',
    cell: ({ row }) => (
      <div className="max-w-[200px]">
        <TlsSummary facts={tlsFacts(row.original)} fallback={<EmptyCell />} />
      </div>
    ),
  },
]

export const websitesConfig: AssetPageConfig = {
  type: 'application',
  subType: 'website',
  label: 'Website',
  labelPlural: 'Websites',
  description: 'Manage your web application assets',
  icon: MonitorSmartphone,
  iconColor: 'text-blue-500',
  gradientFrom: 'from-blue-500/20',
  gradientVia: 'via-blue-500/10',

  columns,

  formFields: [
    {
      name: 'name',
      label: 'URL',
      type: 'text',
      placeholder: 'https://example.com',
      required: true,
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      placeholder: 'Optional description',
      fullWidth: true,
    },
    {
      name: 'technology',
      label: 'Technology (comma separated)',
      type: 'text',
      placeholder: 'React, Node.js, PostgreSQL',
      isMetadata: true,
    },
    {
      name: 'http_status',
      label: 'HTTP Status Code',
      type: 'number',
      placeholder: '200',
      isMetadata: true,
    },
    {
      name: 'response_time',
      label: 'Response Time (ms)',
      type: 'number',
      placeholder: '150',
      isMetadata: true,
    },
    {
      name: 'server',
      label: 'Server',
      type: 'text',
      placeholder: 'nginx/1.21.0',
      isMetadata: true,
    },
    {
      name: 'ssl',
      label: 'SSL/TLS Enabled',
      type: 'boolean',
      isMetadata: true,
      defaultValue: true,
    },
    {
      name: 'tags',
      label: 'Tags (comma separated)',
      type: 'tags',
      placeholder: 'production, critical',
      fullWidth: true,
    },
  ],

  includeGroupSelect: true,

  countBy: ['ssl'],

  statsCards: [
    {
      title: 'SSL Secure',
      icon: ShieldCheck,
      compute: (_assets, stats) => stats.metadataCounts?.ssl?.true ?? 0,
      variant: 'success',
    },
    {
      title: 'SSL Insecure',
      icon: ShieldX,
      compute: (_assets, stats) => stats.metadataCounts?.ssl?.false ?? 0,
      variant: 'danger',
    },
    {
      title: 'With Findings',
      icon: AlertTriangle,
      compute: (_assets, stats) => stats.withFindings,
      variant: 'warning',
    },
  ],

  detailStats: [
    {
      icon: Shield,
      iconBg: 'bg-orange-500/10',
      iconColor: 'text-orange-500',
      label: 'Risk Score',
      getValue: (asset) => asset.riskScore,
    },
    {
      icon: AlertTriangle,
      iconBg: 'bg-red-500/10',
      iconColor: 'text-red-500',
      label: 'Findings',
      getValue: (asset) => asset.findingCount,
    },
    {
      icon: Zap,
      iconBg: 'bg-blue-500/10',
      iconColor: 'text-blue-500',
      label: 'Response (ms)',
      getValue: (asset) => responseTimeMs(asset) ?? '—',
    },
  ],

  detailSections: [
    {
      title: 'Website Information',
      fields: [
        {
          label: 'HTTP Status',
          getValue: (asset) =>
            httpStatusCode(asset) === null ? null : (
              <HttpStatusChip status={httpStatusCode(asset)} chain={redirectChain(asset)} />
            ),
          notCollected: 'HTTP status',
        },
        {
          label: 'TLS',
          getValue: (asset) =>
            tlsFacts(asset).kind === 'not_collected' ? null : (
              <TlsSummary facts={tlsFacts(asset)} />
            ),
          notCollected: (asset) => tlsNotCollected(tlsFacts(asset)),
        },
        {
          label: 'Title',
          getValue: (asset) => pageTitle(asset),
          fullWidth: true,
          notCollected: 'page title',
        },
        {
          label: 'Web server',
          getValue: (asset) => webServer(asset),
          notCollected: 'web server',
        },
        {
          // Optional facts: not every site has a CDN or reports a type.
          label: 'Content type',
          getValue: (asset) => contentType(asset),
        },
        {
          label: 'CDN',
          getValue: (asset) => cdnName(asset),
        },
        {
          label: 'IP addresses',
          getValue: (asset) => {
            const ips = ipAddresses(asset)
            return ips.length ? (
              <ChipRow>
                <OverflowChips label="IP" values={ips} />
              </ChipRow>
            ) : null
          },
          notCollected: 'IP addresses',
        },
        {
          label: 'Redirects to',
          getValue: (asset) => {
            const target = redirectTarget(asset)
            return target ? (
              <SafeExternalLink
                href={target}
                className="break-all font-mono text-xs hover:underline"
              >
                {target}
              </SafeExternalLink>
            ) : null
          },
          fullWidth: true,
        },
      ],
    },
    {
      title: 'Technology Stack',
      fields: [
        {
          label: 'Technologies',
          getValue: (asset) =>
            technologies(asset) === null ? null : (
              <ChipRow>
                <TechChips technologies={technologies(asset)} max={Infinity} />
              </ChipRow>
            ),
          fullWidth: true,
          notCollected: 'technologies',
        },
      ],
    },
  ],

  exportFields: [
    { header: 'URL', accessor: (a) => a.name },
    {
      header: 'Technologies',
      accessor: (a) => (technologies(a) ?? []).map(formatTechnology).join(';'),
    },
    { header: 'TLS', accessor: (a) => tlsLabel(a) },
    { header: 'HTTP Status', accessor: (a) => httpStatusCode(a) ?? '' },
    { header: 'Title', accessor: (a) => pageTitle(a) ?? '' },
    { header: 'Web server', accessor: (a) => webServer(a) ?? '' },
    { header: 'Status', accessor: (a) => a.status },
    { header: 'Risk Score', accessor: (a) => a.riskScore },
    { header: 'Findings', accessor: (a) => a.findingCount },
  ],

  copyAction: {
    label: 'Copy URL',
    getValue: (asset) => asset.name,
  },

  customFilter: {
    label: 'TLS',
    options: [
      { label: 'Served over TLS', value: 'secure' },
      { label: 'No TLS', value: 'insecure' },
      { label: 'Not collected', value: 'unknown' },
    ],
    filterFn: (asset, value) => {
      const kind = tlsFacts(asset).kind
      if (value === 'unknown') return kind === 'not_collected'
      return value === 'secure' ? kind === 'cert' || kind === 'tls' : kind === 'none'
    },
  },
}
