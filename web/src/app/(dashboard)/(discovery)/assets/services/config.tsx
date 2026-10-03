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
  TechChips,
  TlsSummary,
  UnknownChip,
} from '@/features/assets/components/service-cells'

// The services page lists every `service` asset: HTTP services from httpx
// (sub_type http, nested `service.*` + `status_code`, `technologies`),
// open ports from naabu (sub_type open_port, flat `port`/`protocol`), and
// services from nmap-style scans. Each cell reads both shapes through
// service-facts; nothing is defaulted (no "TCP", no port 0).

/** HTTP-only facts (status, technologies) do not apply to an SSH port. */
const isWeb = (a: Asset) => isHttpService(a) || a.subType === 'discovered_url'

const notApplicable = (what: string) => (
  <span className="text-xs text-muted-foreground" title={`Not an HTTP service: no ${what}`}>
    —
  </span>
)
const unknownText = (text = 'Unknown') => <span className="text-muted-foreground">{text}</span>

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
        if (port === null) return <UnknownChip>Unknown</UnknownChip>
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
        if (!protocol) return <UnknownChip>Unknown</UnknownChip>
        return <FactChip tone="muted">{protocol.toUpperCase()}</FactChip>
      },
    },
    {
      id: 'version',
      header: 'Product',
      cell: ({ row }) => {
        const label = productLabel(row.original)
        if (!label) return <UnknownChip>Not collected</UnknownChip>
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
            <TechChips technologies={technologies(row.original)} max={2} />
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
          <TlsSummary facts={tlsFacts(row.original)} />
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
          getValue: (asset) => serviceProtocol(asset)?.toUpperCase() ?? unknownText(),
        },
        {
          label: 'Transport',
          getValue: (asset) => serviceTransport(asset)?.toUpperCase() ?? unknownText(),
        },
        {
          label: 'Product',
          getValue: (asset) => productLabel(asset) ?? unknownText('Not collected'),
        },
        {
          label: 'TLS',
          getValue: (asset) => <TlsSummary facts={tlsFacts(asset)} explainMissing />,
        },
        {
          label: 'IP addresses',
          getValue: (asset) => {
            const ips = ipAddresses(asset)
            return ips.length ? (
              <ChipRow>
                <OverflowChips label="IP" values={ips} />
              </ChipRow>
            ) : (
              unknownText()
            )
          },
        },
        {
          label: 'Banner',
          fullWidth: true,
          getValue: (asset) => {
            const banner = serviceBanner(asset)
            if (!banner) return unknownText('Not collected')
            return (
              <code className="block text-xs bg-muted p-2 rounded overflow-x-auto">{banner}</code>
            )
          },
        },
      ],
    },
    {
      title: 'Web',
      fields: [
        {
          label: 'HTTP status',
          getValue: (asset) =>
            isWeb(asset) ? (
              <HttpStatusChip status={httpStatusCode(asset)} chain={redirectChain(asset)} />
            ) : (
              notApplicable('HTTP status')
            ),
        },
        {
          label: 'Title',
          getValue: (asset) =>
            isWeb(asset)
              ? (pageTitle(asset) ?? unknownText('Not collected'))
              : notApplicable('title'),
        },
        {
          label: 'Technologies',
          fullWidth: true,
          getValue: (asset) =>
            isWeb(asset) ? (
              <ChipRow>
                <TechChips technologies={technologies(asset)} max={Infinity} />
              </ChipRow>
            ) : (
              notApplicable('web technologies')
            ),
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
