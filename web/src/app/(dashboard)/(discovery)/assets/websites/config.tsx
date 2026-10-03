import type { ColumnDef } from '@tanstack/react-table'
import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import type { Asset } from '@/features/assets'
import { toStringArray } from '@/features/assets/lib/property-utils'
import { httpStatus, websiteTLS } from '@/features/assets/lib/certificate-facts'
import { Badge } from '@/components/ui/badge'
import {
  MonitorSmartphone,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Shield,
  Zap,
  HelpCircle,
} from 'lucide-react'

const columns: ColumnDef<Asset>[] = [
  {
    id: 'technology',
    header: 'Technology',
    cell: ({ row }) => {
      const raw = row.original.metadata.technology
      const tech: string[] = Array.isArray(raw) ? raw : raw ? [String(raw)] : []
      return (
        <div className="flex flex-wrap gap-1 max-w-[150px]">
          {tech.slice(0, 2).map((t) => (
            <Badge key={t} variant="outline" className="text-xs">
              {t}
            </Badge>
          ))}
          {tech.length > 2 && (
            <Badge variant="outline" className="text-xs">
              +{tech.length - 2}
            </Badge>
          )}
        </div>
      )
    },
  },
  {
    id: 'ssl',
    header: 'SSL',
    // Unknown when nothing recorded TLS: a missing flag is not "insecure".
    cell: ({ row }) => {
      const tls = websiteTLS(row.original)
      if (tls === null)
        return (
          <div className="flex items-center gap-1 text-muted-foreground">
            <HelpCircle className="h-4 w-4" />
            <span className="text-xs">Unknown</span>
          </div>
        )
      return tls ? (
        <div className="flex items-center gap-1 text-green-500">
          <ShieldCheck className="h-4 w-4" />
          <span className="text-xs">Secure</span>
        </div>
      ) : (
        <div className="flex items-center gap-1 text-red-500">
          <ShieldX className="h-4 w-4" />
          <span className="text-xs">Insecure</span>
        </div>
      )
    },
  },
  {
    id: 'http_status',
    header: 'Status Code',
    cell: ({ row }) => {
      // No probe recorded a status: show "-", never a default 200.
      const status = httpStatus(row.original)
      if (status === null) return <span className="text-muted-foreground">-</span>
      const statusClass =
        status >= 200 && status < 300
          ? 'text-green-500 bg-green-500/10'
          : status >= 300 && status < 400
            ? 'text-blue-500 bg-blue-500/10'
            : status >= 400 && status < 500
              ? 'text-orange-500 bg-orange-500/10'
              : 'text-red-500 bg-red-500/10'
      return (
        <Badge variant="outline" className={statusClass}>
          {status}
        </Badge>
      )
    },
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
      getValue: (asset) => (asset.metadata.response_time as number) || '-',
    },
  ],

  detailSections: [
    {
      title: 'Website Information',
      fields: [
        {
          label: 'HTTP Status',
          getValue: (asset) => {
            const status = httpStatus(asset)
            if (status === null) return <span className="text-muted-foreground">Unknown</span>
            return (
              <Badge variant="outline" className={status < 400 ? 'text-green-500' : 'text-red-500'}>
                {status}
              </Badge>
            )
          },
        },
        {
          label: 'SSL Certificate',
          getValue: (asset) => {
            const tls = websiteTLS(asset)
            return tls === null ? 'Unknown' : tls ? 'Served over TLS' : 'Not served over TLS'
          },
        },
        {
          label: 'Server',
          getValue: (asset) => (asset.metadata.server as string) || '-',
          fullWidth: true,
        },
      ],
    },
    {
      title: 'Technology Stack',
      fields: [
        {
          label: 'Technologies',
          getValue: (asset) => {
            const tech = (() => {
              const r = asset.metadata.technology
              return Array.isArray(r) ? r : r ? [String(r)] : []
            })()
            if (!tech.length) return '-'
            return (
              <div className="flex flex-wrap gap-2">
                {tech.map((t) => (
                  <Badge key={t} variant="secondary">
                    {t}
                  </Badge>
                ))}
              </div>
            )
          },
          fullWidth: true,
        },
      ],
    },
  ],

  exportFields: [
    { header: 'URL', accessor: (a) => a.name },
    {
      header: 'Technology',
      accessor: (a) => {
        const raw = a.metadata.technology
        const tech = toStringArray(raw)
        return tech.join(';')
      },
    },
    {
      header: 'SSL',
      accessor: (a) => {
        const tls = websiteTLS(a)
        return tls === null ? '' : tls ? 'Yes' : 'No'
      },
    },
    { header: 'HTTP Status', accessor: (a) => httpStatus(a) ?? '' },
    { header: 'Status', accessor: (a) => a.status },
    { header: 'Risk Score', accessor: (a) => a.riskScore },
    { header: 'Findings', accessor: (a) => a.findingCount },
  ],

  copyAction: {
    label: 'Copy URL',
    getValue: (asset) => asset.name,
  },

  customFilter: {
    label: 'SSL Status',
    options: [
      { label: 'Secure', value: 'secure' },
      { label: 'Insecure', value: 'insecure' },
      { label: 'Unknown', value: 'unknown' },
    ],
    filterFn: (asset, value) => {
      const tls = websiteTLS(asset)
      if (value === 'unknown') return tls === null
      return value === 'secure' ? tls === true : tls === false
    },
  },
}
