'use client'

import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import { Badge } from '@/components/ui/badge'
import { Globe, AlertTriangle, Shield } from 'lucide-react'
import {
  cnames,
  dnsRecordTypes,
  domainExpiry,
  ipAddresses,
  nameservers,
  registrar,
} from '@/features/assets/lib/service-facts'
import {
  ChipMono,
  ChipRow,
  FactChip,
  OverflowChips,
  UnknownChip,
} from '@/features/assets/components/service-cells'

// DNS facts come from `domain.dns_records[]` (dnsx via ingest) or the flat
// keys the collector path writes (`resolved_ips`, `cname_target`,
// `dns_record_types`); registration from `domain.{registrar,expires_at}` or
// the form's `registrar` / `expiry_date`. All read through service-facts.

const unknownText = (text = 'Unknown') => <span className="text-muted-foreground">{text}</span>

export const domainsConfig: AssetPageConfig = {
  type: 'domain',
  types: ['domain', 'subdomain'],
  label: 'Domain',
  labelPlural: 'Domains & Subdomains',
  description: 'Manage your domain assets and track domain hierarchy',
  icon: Globe,
  iconColor: 'text-blue-500',
  gradientFrom: 'from-blue-500/20',
  gradientVia: 'via-blue-500/10',

  defaultSort: { field: 'name', direction: 'asc' },

  columns: [
    {
      id: 'domainType',
      header: 'Type',
      cell: ({ row }) => {
        // Use asset_type from DB — reliable regardless of pagination
        const isRoot = row.original.type === 'domain'
        return isRoot ? (
          <Badge variant="default" className="text-xs px-1.5 py-0">
            Root
          </Badge>
        ) : (
          <Badge variant="outline" className="text-xs px-1.5 py-0 text-muted-foreground">
            Sub
          </Badge>
        )
      },
    },
    {
      id: 'dnsInfo',
      header: 'DNS',
      cell: ({ row }) => {
        const ips = ipAddresses(row.original)
        const targets = cnames(row.original)
        if (ips.length === 0 && targets.length === 0) {
          const reg = registrar(row.original)
          if (row.original.type === 'domain' && reg)
            return (
              <span className="block max-w-[200px] truncate text-sm" title={reg}>
                {reg}
              </span>
            )
          return <UnknownChip>Not resolved</UnknownChip>
        }
        return (
          <ChipRow className="max-w-[260px]">
            <OverflowChips label="CNAME" values={targets} />
            <OverflowChips label="IP" values={ips} />
          </ChipRow>
        )
      },
    },
  ],

  formFields: [
    {
      name: 'name',
      label: 'Domain Name',
      type: 'text',
      placeholder: 'example.com',
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
      name: 'registrar',
      label: 'Registrar',
      type: 'text',
      placeholder: 'GoDaddy, Cloudflare...',
      isMetadata: true,
    },
    {
      name: 'expiry_date',
      label: 'Expiry Date',
      type: 'text',
      placeholder: 'YYYY-MM-DD',
      isMetadata: true,
    },
    {
      name: 'nameservers',
      label: 'Nameservers (comma separated)',
      type: 'text',
      placeholder: 'ns1.example.com, ns2.example.com',
      isMetadata: true,
      fullWidth: true,
    },
    {
      name: 'tags',
      label: 'Tags',
      type: 'tags',
      placeholder: 'production, critical',
      fullWidth: true,
    },
  ],

  includeGroupSelect: true,

  statsCards: [
    {
      title: 'Root Domains',
      icon: Globe,
      compute: (_assets, stats) => stats.byType?.domain ?? 0,
    },
    {
      title: 'Subdomains',
      icon: Globe,
      compute: (_assets, stats) => stats.byType?.subdomain ?? 0,
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
  ],

  detailSections: [
    {
      title: 'Domain Information',
      fields: [
        {
          label: 'Registrar',
          getValue: (asset) => registrar(asset) ?? unknownText(),
        },
        {
          label: 'Expiry Date',
          getValue: (asset) => domainExpiry(asset)?.toLocaleDateString() ?? unknownText(),
        },
        {
          label: 'Root Domain',
          getValue: (asset) =>
            ((asset.metadata as Record<string, unknown>).root_domain as string) || unknownText(),
        },
        {
          label: 'Collector',
          getValue: (asset) => {
            const meta = asset.metadata as Record<string, unknown>
            const type = (meta.collector_type as string) || ''
            const source = (meta.collector_source as string) || (meta.source as string) || ''
            if (!type && !source) return unknownText()
            return type ? `${type}${source ? ` (${source})` : ''}` : source
          },
        },
      ],
    },
    {
      title: 'DNS Records',
      fields: [
        {
          label: 'Record Types',
          getValue: (asset) => {
            const types = dnsRecordTypes(asset)
            if (types.length === 0) return unknownText('Not collected')
            return (
              <ChipRow>
                {types.map((t) => (
                  <FactChip key={t} tone="muted">
                    <ChipMono>{t}</ChipMono>
                  </FactChip>
                ))}
              </ChipRow>
            )
          },
        },
        {
          label: 'Resolved IPs',
          getValue: (asset) => {
            const ipList = ipAddresses(asset)
            if (ipList.length === 0) return unknownText('None recorded')
            return (
              <ChipRow>
                {ipList.map((ip) => (
                  <FactChip key={ip} tone="muted">
                    <ChipMono>{ip}</ChipMono>
                  </FactChip>
                ))}
              </ChipRow>
            )
          },
          fullWidth: true,
        },
        {
          label: 'CNAME Target',
          getValue: (asset) => {
            const targets = cnames(asset)
            if (targets.length === 0) return unknownText('None recorded')
            return (
              <ChipRow>
                {targets.map((t) => (
                  <FactChip key={t} tone="muted">
                    <ChipMono>{t}</ChipMono>
                  </FactChip>
                ))}
              </ChipRow>
            )
          },
          fullWidth: true,
        },
        {
          label: 'Nameservers',
          getValue: (asset) => {
            const ns = nameservers(asset)
            if (ns.length === 0) return unknownText('None recorded')
            return (
              <ChipRow>
                {ns.map((n) => (
                  <FactChip key={n} tone="muted">
                    <ChipMono>{n}</ChipMono>
                  </FactChip>
                ))}
              </ChipRow>
            )
          },
          fullWidth: true,
        },
      ],
    },
  ],

  exportFields: [
    { header: 'Name', accessor: (a) => a.name },
    { header: 'Type', accessor: (a) => (a.type === 'domain' ? 'Root' : 'Subdomain') },
    { header: 'Registrar', accessor: (a) => registrar(a) ?? '' },
    { header: 'Expiry Date', accessor: (a) => domainExpiry(a)?.toISOString().slice(0, 10) ?? '' },
    { header: 'IP addresses', accessor: (a) => ipAddresses(a).join(';') },
    { header: 'CNAME', accessor: (a) => cnames(a).join(';') },
    { header: 'Status', accessor: (a) => a.status },
    { header: 'Risk Score', accessor: (a) => a.riskScore },
    { header: 'Findings', accessor: (a) => a.findingCount },
  ],

  copyAction: {
    label: 'Copy Name',
    getValue: (asset) => asset.name,
  },
}
