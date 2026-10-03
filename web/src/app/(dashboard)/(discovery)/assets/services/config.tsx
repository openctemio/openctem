'use client'

import { Server, Network, CheckCircle, AlertTriangle, Shield } from 'lucide-react'
import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import type { Asset } from '@/features/assets'
import {
  formatTechnology,
  httpStatusCode,
  ipAddresses,
  isHttpService,
  pageTitle,
  redirectChain,
  serviceBanner,
  serviceName,
  servicePort,
  serviceProduct,
  serviceProtocol,
  serviceTransport,
  serviceVersion,
  technologies,
  tlsFacts,
  webServer,
} from '@/features/assets/lib/service-facts'
import {
  ChipMono,
  ChipRow,
  FactChip,
  HttpStatusChip,
  OverflowChips,
  EmptyCell,
  TechChips,
  TlsSummary,
  tlsNotCollected,
} from '@/features/assets/components/service-cells'

// The services page lists every `service` asset: HTTP services from httpx
// (sub_type http, nested `service.*` + `status_code`, `technologies`),
// open ports from naabu (sub_type open_port, flat `port`/`protocol`), and
// services from nmap-style scans. Each cell reads both shapes through
// service-facts; nothing is defaulted (no "TCP", no port 0). A fact nothing
// collected is an empty cell (`—`) in the list and one "Not collected yet"
// line in the drawer (ui-style-contract §7, "Unknown facts").

/** HTTP-only facts (status, technologies) do not apply to an SSH port. */
const isWeb = (a: Asset) => isHttpService(a) || a.subType === 'discovered_url'

const notApplicable = (what: string) => (
  <span className="text-xs text-muted-foreground" title={`Not an HTTP service: no ${what}`}>
    —
  </span>
)

/** "nginx/1.25.3" for a web service, "OpenSSH 9.6p1" for an nmap one. */
function productLabel(a: Asset): string | undefined {
  if (isHttpService(a)) return webServer(a)
  const product = serviceProduct(a) ?? serviceName(a)
  const version = serviceVersion(a)
  return [product, version].filter(Boolean).join(' ') || undefined
}

export const servicesConfig: AssetPageConfig = {
  type: 'service',
  label: 'Service',
  labelPlural: 'Services',
  description: 'Manage your network services and ports',
  icon: Server,
  iconColor: 'text-blue-500',
  gradientFrom: 'from-blue-500/20',
  gradientVia: 'via-blue-500/10',

  columns: [
    {
      id: 'port',
      header: 'Port',
      cell: ({ row }) => {
        const port = servicePort(row.original)
        if (port === null) return <EmptyCell />
        return (
          <FactChip tone="muted">
            <ChipMono>{port}</ChipMono>
          </FactChip>
        )
      },
    },
    {
      id: 'protocol',
      header: 'Protocol',
      cell: ({ row }) => {
        const protocol = serviceProtocol(row.original)
        if (!protocol) return <EmptyCell />
        return <FactChip tone="muted">{protocol.toUpperCase()}</FactChip>
      },
    },
    {
      id: 'version',
      header: 'Product',
      cell: ({ row }) => {
        const label = productLabel(row.original)
        if (!label) return <EmptyCell />
        return (
          <span className="block max-w-[180px] truncate text-sm" title={label}>
            {label}
          </span>
        )
      },
    },
    {
      id: 'http_status',
      header: 'Status',
      cell: ({ row }) =>
        isWeb(row.original) ? (
          <HttpStatusChip
            status={httpStatusCode(row.original)}
            chain={redirectChain(row.original)}
            fallback={<EmptyCell />}
          />
        ) : (
          notApplicable('HTTP status')
        ),
    },
    {
      id: 'technology',
      header: 'Technologies',
      cell: ({ row }) =>
        isWeb(row.original) ? (
          <ChipRow className="max-w-[220px]">
            <TechChips technologies={technologies(row.original)} max={2} fallback={<EmptyCell />} />
          </ChipRow>
        ) : (
          notApplicable('web technologies')
        ),
    },
    {
      id: 'tls',
      header: 'TLS',
      cell: ({ row }) => (
        <div className="max-w-[200px]">
          <TlsSummary facts={tlsFacts(row.original)} fallback={<EmptyCell />} />
        </div>
      ),
    },
  ],

  formFields: [
    {
      name: 'name',
      label: 'Service Name',
      type: 'text',
      placeholder: 'e.g., api.example.com',
      required: true,
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      placeholder: 'Optional description',
    },
    {
      name: 'port',
      label: 'Port',
      type: 'number',
      placeholder: '443',
      isMetadata: true,
      required: true,
    },
    {
      name: 'protocol',
      label: 'Protocol',
      type: 'select',
      isMetadata: true,
      defaultValue: 'tcp',
      options: [
        { label: 'TCP', value: 'tcp' },
        { label: 'UDP', value: 'udp' },
      ],
    },
    {
      name: 'version',
      label: 'Version',
      type: 'text',
      placeholder: 'e.g., OpenSSH 8.4',
      isMetadata: true,
    },
    {
      name: 'technology',
      label: 'Technology',
      type: 'tags',
      placeholder: 'Nginx, Node.js, React',
      isMetadata: true,
    },
    {
      name: 'banner',
      label: 'Banner',
      type: 'textarea',
      placeholder: 'Service banner response',
      isMetadata: true,
    },
    { name: 'tags', label: 'Tags', type: 'tags', placeholder: 'production, critical' },
  ],

  statsCards: [
    {
      title: 'Active',
      icon: CheckCircle,
      compute: (_assets, stats) => stats.byStatus.active ?? 0,
      variant: 'success',
    },
    {
      title: 'Total',
      icon: Server,
      compute: (_assets, stats) => stats.total,
    },
    {
      title: 'With Findings',
      icon: AlertTriangle,
      compute: (_assets, stats) => stats.withFindings,
      variant: 'warning',
    },
  ],

  customFilter: {
    label: 'Protocol',
    options: [
      { label: 'TCP', value: 'tcp' },
      { label: 'UDP', value: 'udp' },
    ],
    filterFn: (asset, value) => serviceTransport(asset) === value,
  },

  copyAction: {
    label: 'Copy Service Info',
    getValue: (asset) => {
      const port = servicePort(asset)
      const protocol = serviceProtocol(asset)
      return [asset.name, port !== null ? `:${port}` : '', protocol ? `/${protocol}` : ''].join('')
    },
  },

  detailStats: [
    {
      icon: Network,
      iconBg: 'bg-blue-500/10',
      iconColor: 'text-blue-500',
      label: 'Port',
      getValue: (asset) => servicePort(asset) ?? '—',
    },
    {
      icon: Shield,
      iconBg: 'bg-orange-500/10',
      iconColor: 'text-orange-500',
      label: 'Risk',
      getValue: (asset) => asset.riskScore,
    },
    {
      icon: AlertTriangle,
      iconBg: 'bg-red-500/10',
      iconColor: 'text-red-500',
      label: 'Findings',
      getValue: (asset) => asset.findingCount,
    },
  ],

  detailSections: [
    {
      title: 'Service Information',
      fields: [
        {
          label: 'Protocol',
          getValue: (asset) => serviceProtocol(asset)?.toUpperCase(),
          notCollected: 'protocol',
        },
        {
          label: 'Transport',
          getValue: (asset) => serviceTransport(asset)?.toUpperCase(),
          notCollected: 'transport',
        },
        {
          label: 'Product',
          getValue: (asset) => productLabel(asset),
          notCollected: 'product',
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
          label: 'Banner',
          fullWidth: true,
          getValue: (asset) => {
            const banner = serviceBanner(asset)
            if (!banner) return null
            return (
              <code className="block text-xs bg-muted p-2 rounded overflow-x-auto">{banner}</code>
            )
          },
          notCollected: 'banner',
        },
      ],
    },
    {
      title: 'Web',
      fields: [
        // HTTP-only facts do not apply to an SSH port: those rows are left
        // out of the drawer, and they are not a gap either.
        {
          label: 'HTTP status',
          getValue: (asset) =>
            isWeb(asset) && httpStatusCode(asset) !== null ? (
              <HttpStatusChip status={httpStatusCode(asset)} chain={redirectChain(asset)} />
            ) : null,
          notCollected: (asset) =>
            isWeb(asset) && httpStatusCode(asset) === null ? 'HTTP status' : null,
        },
        {
          label: 'Title',
          getValue: (asset) => (isWeb(asset) ? pageTitle(asset) : null),
          notCollected: (asset) => (isWeb(asset) && !pageTitle(asset) ? 'page title' : null),
        },
        {
          label: 'Technologies',
          fullWidth: true,
          getValue: (asset) =>
            isWeb(asset) && technologies(asset) !== null ? (
              <ChipRow>
                <TechChips technologies={technologies(asset)} max={Infinity} />
              </ChipRow>
            ) : null,
          notCollected: (asset) =>
            isWeb(asset) && technologies(asset) === null ? 'technologies' : null,
        },
      ],
    },
  ],

  exportFields: [
    { header: 'Name', accessor: (a) => a.name },
    { header: 'Port', accessor: (a) => servicePort(a) ?? '' },
    { header: 'Protocol', accessor: (a) => serviceProtocol(a) ?? '' },
    { header: 'Product', accessor: (a) => productLabel(a) ?? '' },
    { header: 'HTTP Status', accessor: (a) => httpStatusCode(a) ?? '' },
    {
      header: 'Technologies',
      accessor: (a) => (technologies(a) ?? []).map(formatTechnology).join(';'),
    },
    { header: 'Status', accessor: (a) => a.status },
    { header: 'Risk Score', accessor: (a) => a.riskScore },
    { header: 'Findings', accessor: (a) => a.findingCount },
  ],

  includeGroupSelect: true,
}
