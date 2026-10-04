'use client'

import { Badge } from '@/components/ui/badge'
import { Network, Shield, AlertTriangle, CheckCircle } from 'lucide-react'
import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import type { Asset } from '@/features/assets'
import { asnInfo, formatPort, openPorts } from '@/features/assets/lib/service-facts'
import {
  ChipMono,
  ChipRow,
  FactChip,
  OpenPortChips,
  EmptyCell,
} from '@/features/assets/components/service-cells'

// ASN and open ports come from `ip_address.{asn,asn_org,ports[]}` (ingest)
// or the manual form's flat `asn` / `asn_organization` / `open_ports`, read
// through service-facts. No port scan (`null`) is not "no open ports" (`[]`):
// the first is an empty cell in the list and named in the drawer's "Not
// collected yet" line, the second is shown as "No open ports".

// Helper to determine if IP is public or private
function isPublicIp(address: string): boolean {
  if (
    address.startsWith('10.') ||
    address.startsWith('192.168.') ||
    address.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
  ) {
    return false
  }
  if (address.startsWith('127.') || address === '::1') {
    return false
  }
  if (address.startsWith('169.254.') || address.toLowerCase().startsWith('fe80:')) {
    return false
  }
  return true
}

// Helper to detect IP version
function getIpVersion(address: string): 'ipv4' | 'ipv6' {
  return address.includes(':') ? 'ipv6' : 'ipv4'
}

export const ipAddressesConfig: AssetPageConfig = {
  type: 'ip_address',
  label: 'IP Address',
  labelPlural: 'IP Addresses',
  description: 'IPv4 and IPv6 addresses in your infrastructure',
  icon: Network,
  iconColor: 'text-blue-500',
  gradientFrom: 'from-blue-500/20',
  gradientVia: 'via-blue-500/10',

  columns: [
    {
      id: 'asnOrg',
      header: 'ASN / Organization',
      cell: ({ row }) => {
        const { asn, org } = asnInfo(row.original)
        if (!asn && !org) return <EmptyCell />
        return (
          <div className="min-w-0 max-w-[200px]">
            {asn && <p className="font-mono text-sm">{asn}</p>}
            {org && (
              <p className="truncate text-xs text-muted-foreground" title={org}>
                {org}
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: 'ipType',
      header: 'Type',
      cell: ({ row }) => {
        const isPublic = isPublicIp(row.original.name)
        return (
          <Badge variant={isPublic ? 'default' : 'secondary'}>
            {isPublic ? 'Public' : 'Private'}
          </Badge>
        )
      },
    },
    {
      id: 'open_ports',
      header: 'Open Ports',
      cell: ({ row }) => (
        <ChipRow className="max-w-[240px]">
          <OpenPortChips asset={row.original} max={3} fallback={<EmptyCell />} />
        </ChipRow>
      ),
    },
  ],

  formFields: [
    {
      name: 'name',
      label: 'IP Address',
      type: 'text',
      placeholder: '192.168.1.1 or 2001:db8::1',
      required: true,
    },
    { name: 'asn', label: 'ASN', type: 'text', placeholder: 'AS12345', isMetadata: true },
    {
      name: 'asn_organization',
      label: 'Organization',
      type: 'text',
      placeholder: 'Example Corp',
      isMetadata: true,
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      placeholder: 'Optional description',
      fullWidth: true,
    },
    { name: 'tags', label: 'Tags', type: 'tags', placeholder: 'production, web-server' },
  ],

  statsCards: [
    {
      title: 'Active',
      icon: CheckCircle,
      compute: (_assets, stats) => stats.byStatus?.active ?? 0,
      variant: 'success',
    },
    {
      title: 'With Findings',
      icon: AlertTriangle,
      compute: (_assets, stats) => stats.withFindings,
      variant: 'warning',
    },
  ],

  customFilter: {
    label: 'IP Type',
    options: [
      { label: 'Public', value: 'public' },
      { label: 'Private', value: 'private' },
    ],
    filterFn: (asset: Asset, value: string) => {
      const isPublic = isPublicIp(asset.name)
      return value === 'public' ? isPublic : !isPublic
    },
  },

  copyAction: {
    label: 'Copy Address',
    getValue: (asset: Asset) => asset.name,
  },

  detailStats: [
    {
      icon: Shield,
      iconBg: 'bg-orange-500/10',
      iconColor: 'text-orange-500',
      label: 'Risk Score',
      getValue: (asset: Asset) => asset.riskScore,
    },
    {
      icon: AlertTriangle,
      iconBg: 'bg-red-500/10',
      iconColor: 'text-red-500',
      label: 'Findings',
      getValue: (asset: Asset) => asset.findingCount,
    },
  ],

  detailSections: [
    {
      title: 'IP Information',
      fields: [
        {
          label: 'Version',
          getValue: (asset: Asset) => getIpVersion(asset.name).toUpperCase(),
        },
        {
          label: 'Type',
          getValue: (asset: Asset) => (isPublicIp(asset.name) ? 'Public' : 'Private'),
        },
        {
          label: 'ASN',
          getValue: (asset: Asset) => asnInfo(asset).asn,
          notCollected: 'ASN',
        },
        {
          label: 'Organization',
          getValue: (asset: Asset) => asnInfo(asset).org,
          notCollected: 'organization',
        },
        {
          label: 'Open Ports',
          fullWidth: true,
          getValue: (asset: Asset) => {
            const ports = openPorts(asset)
            if (ports === null) return null
            if (ports.length === 0) return <span className="text-muted-foreground">None open</span>
            return (
              <ChipRow>
                {ports.map((p) => (
                  <FactChip key={formatPort(p)} tone="muted" title={p.service}>
                    <ChipMono>{formatPort(p)}</ChipMono>
                    {p.service && <span>{p.service}</span>}
                  </FactChip>
                ))}
              </ChipRow>
            )
          },
          notCollected: 'open ports',
        },
      ],
    },
  ],

  exportFields: [
    { header: 'IP Address', accessor: (a: Asset) => a.name },
    { header: 'Version', accessor: (a: Asset) => getIpVersion(a.name) },
    { header: 'Type', accessor: (a: Asset) => (isPublicIp(a.name) ? 'Public' : 'Private') },
    { header: 'ASN', accessor: (a: Asset) => asnInfo(a).asn ?? '' },
    { header: 'Organization', accessor: (a: Asset) => asnInfo(a).org ?? '' },
    {
      header: 'Open Ports',
      accessor: (a: Asset) => (openPorts(a) ?? []).map(formatPort).join(';'),
    },
    { header: 'Status', accessor: (a: Asset) => a.status },
    { header: 'Risk Score', accessor: (a: Asset) => a.riskScore },
    { header: 'Findings', accessor: (a: Asset) => a.findingCount },
  ],

  includeGroupSelect: false,
}
