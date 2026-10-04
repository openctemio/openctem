'use client'

import { ShieldCheck, CheckCircle, XCircle, AlertTriangle, Shield } from 'lucide-react'
import type { AssetPageConfig } from '@/features/assets/types/page-config.types'
import type { Asset } from '@/features/assets'
import {
  certDaysLeft,
  certFingerprint,
  certIsWildcard,
  certIssuer,
  certKeyAlgorithm,
  certKeySize,
  certNotAfter,
  certNotBefore,
  certSans,
  certSelfSigned,
  certSerial,
  certSignatureAlgorithm,
  certStatus,
  certSubject,
  type CertStatus,
} from '@/features/assets/lib/certificate-facts'
import { recordedCertificate } from '@/features/assets/lib/service-facts'
import {
  CertExpiryChip,
  ChipMono,
  ChipRow,
  FactChip,
  EmptyCell,
  OverflowChips,
} from '@/features/assets/components/service-cells'

// Validity comes from certificate-facts: it reads both the form keys and the
// nested map ingest writes, and a certificate without a date is "unknown",
// never "valid". The expiry chip is the shared one every TLS cell uses.
// A fact nothing recorded is an empty cell (`—`) in the list and one "Not
// collected yet" line in the drawer (ui-style-contract §7); the Validity
// filter keeps its "Unknown" value so those certificates stay findable.
const getCertStatus = (asset: Asset): CertStatus => certStatus(asset)
const getDaysUntilExpiry = (asset: Asset): number | null => certDaysLeft(asset)
const fmtDate = (d: Date | null) => (d ? d.toLocaleDateString() : null)
const yesNo = (v: boolean | null) => (v === null ? null : v ? 'Yes' : 'No')

/** Whether the certificate's expiry was recorded (so its validity is known). */
function hasExpiry(asset: Asset): boolean {
  const cert = recordedCertificate(asset)
  return cert !== null && cert.status !== 'unknown'
}

function ExpiryCell({ asset }: { asset: Asset }) {
  const cert = recordedCertificate(asset)
  return cert ? <CertExpiryChip cert={cert} fallback={<EmptyCell />} /> : <EmptyCell />
}

export const certificatesConfig: AssetPageConfig = {
  type: 'certificate',
  label: 'Certificate',
  labelPlural: 'Certificates',
  description: 'Manage SSL/TLS certificate assets in your infrastructure',
  icon: ShieldCheck,
  iconColor: 'text-green-500',
  gradientFrom: 'from-green-500/20',
  gradientVia: 'via-green-500/10',

  columns: [
    {
      id: 'issuer',
      header: 'Issuer',
      cell: ({ row }) => {
        const issuer = certIssuer(row.original)
        if (!issuer) return <EmptyCell />
        return (
          <span className="block max-w-[180px] truncate text-muted-foreground" title={issuer}>
            {issuer}
          </span>
        )
      },
    },
    {
      id: 'validUntil',
      accessorFn: (row) => certNotAfter(row)?.toISOString() ?? '',
      header: 'Valid Until',
      cell: ({ row }) => {
        const notAfter = certNotAfter(row.original)
        if (!notAfter) return <EmptyCell />
        return <span className="text-sm tabular-nums">{notAfter.toLocaleDateString()}</span>
      },
    },
    {
      id: 'certStatus',
      header: 'Validity',
      cell: ({ row }) => <ExpiryCell asset={row.original} />,
    },
    {
      id: 'sans',
      header: 'SANs',
      cell: ({ row }) => {
        const sans = certSans(row.original)
        if (sans.length === 0) return <EmptyCell />
        return (
          <ChipRow className="max-w-[240px]">
            <OverflowChips label="SAN" values={sans} />
          </ChipRow>
        )
      },
    },
  ],

  formFields: [
    {
      name: 'name',
      label: 'Certificate Name / CN',
      type: 'text',
      placeholder: '*.example.com',
      required: true,
    },
    {
      name: 'cert_issuer',
      label: 'Issuer',
      type: 'text',
      placeholder: "Let's Encrypt, DigiCert...",
      isMetadata: true,
    },
    {
      name: 'cert_subject',
      label: 'Subject',
      type: 'text',
      placeholder: 'CN=*.example.com',
      isMetadata: true,
    },
    {
      name: 'cert_not_before',
      label: 'Valid From',
      type: 'text',
      placeholder: 'YYYY-MM-DD',
      isMetadata: true,
    },
    {
      name: 'cert_not_after',
      label: 'Valid Until',
      type: 'text',
      placeholder: 'YYYY-MM-DD',
      isMetadata: true,
    },
    {
      name: 'cert_signature_algorithm',
      label: 'Signature Algorithm',
      type: 'text',
      placeholder: 'SHA256withRSA',
      isMetadata: true,
    },
    {
      name: 'cert_key_size',
      label: 'Key Size (bits)',
      type: 'text',
      placeholder: '2048',
      isMetadata: true,
    },
    {
      name: 'cert_serial_number',
      label: 'Serial Number',
      type: 'text',
      placeholder: '03:A1:...',
      isMetadata: true,
      fullWidth: true,
    },
    {
      name: 'cert_sans',
      label: 'Subject Alternative Names (comma separated)',
      type: 'text',
      placeholder: 'example.com, *.example.com, api.example.com',
      isMetadata: true,
      fullWidth: true,
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      placeholder: 'Optional description',
      fullWidth: true,
    },
    {
      name: 'tags',
      label: 'Tags',
      type: 'tags',
      placeholder: 'production, wildcard, lets-encrypt',
    },
  ],

  statsCards: [
    {
      title: 'Active',
      icon: CheckCircle,
      compute: (_assets, stats) => stats.byStatus?.active ?? 0,
      variant: 'success',
    },
    {
      title: 'Inactive',
      icon: XCircle,
      compute: (_assets, stats) => stats.byStatus?.inactive ?? 0,
      variant: 'danger',
    },
    {
      title: 'With Findings',
      icon: AlertTriangle,
      compute: (_assets, stats) => stats.withFindings,
      variant: 'warning',
    },
  ],

  customFilter: {
    label: 'Validity',
    options: [
      { label: 'Valid', value: 'valid' },
      { label: 'Expiring', value: 'expiring' },
      { label: 'Expired', value: 'expired' },
      { label: 'Unknown', value: 'unknown' },
    ],
    filterFn: (asset: Asset, value: string) => getCertStatus(asset) === value,
  },

  copyAction: {
    label: 'Copy Name',
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
      title: 'Validity',
      fields: [
        {
          label: 'Status',
          getValue: (asset: Asset) => (hasExpiry(asset) ? <ExpiryCell asset={asset} /> : null),
          fullWidth: true,
          notCollected: 'expiry',
        },
      ],
    },
    {
      title: 'Certificate Details',
      fields: [
        {
          label: 'Issuer',
          getValue: (asset: Asset) => certIssuer(asset),
          notCollected: 'issuer',
        },
        {
          label: 'Subject',
          getValue: (asset: Asset) => certSubject(asset),
          notCollected: 'subject',
        },
        {
          label: 'Valid From',
          getValue: (asset: Asset) => fmtDate(certNotBefore(asset)),
          notCollected: 'valid from',
        },
        {
          label: 'Valid Until',
          getValue: (asset: Asset) => fmtDate(certNotAfter(asset)),
          notCollected: 'valid until',
        },
        {
          label: 'Algorithm',
          getValue: (asset: Asset) => certSignatureAlgorithm(asset),
          notCollected: 'algorithm',
        },
        {
          label: 'Key',
          getValue: (asset: Asset) => {
            const size = certKeySize(asset)
            const algo = certKeyAlgorithm(asset)
            if (!size && !algo) return null
            return [algo, size ? `${size} bits` : ''].filter(Boolean).join(' ')
          },
          notCollected: 'key',
        },
        {
          label: 'Serial Number',
          getValue: (asset: Asset) => {
            const serial = certSerial(asset)
            return serial ? <span className="break-all font-mono text-xs">{serial}</span> : null
          },
          notCollected: 'serial number',
        },
        {
          label: 'Wildcard',
          getValue: (asset: Asset) => yesNo(certIsWildcard(asset)),
          notCollected: 'wildcard',
        },
        {
          label: 'Self-signed',
          getValue: (asset: Asset) => yesNo(certSelfSigned(asset)),
          notCollected: 'self-signed',
        },
        {
          label: 'Fingerprint',
          getValue: (asset: Asset) => {
            const fp = certFingerprint(asset)
            return fp ? <span className="break-all font-mono text-xs">{fp}</span> : null
          },
          notCollected: 'fingerprint',
        },
      ],
    },
    {
      title: 'Subject Alternative Names',
      fields: [
        {
          label: 'SANs',
          fullWidth: true,
          getValue: (asset: Asset) => {
            const sans = certSans(asset)
            if (sans.length === 0) return null
            return (
              <ChipRow>
                {sans.map((san) => (
                  <FactChip key={san} tone="muted">
                    <ChipMono>{san}</ChipMono>
                  </FactChip>
                ))}
              </ChipRow>
            )
          },
          notCollected: 'SANs',
        },
      ],
    },
  ],

  exportFields: [
    { header: 'Certificate', accessor: (a: Asset) => a.name },
    { header: 'Issuer', accessor: (a: Asset) => certIssuer(a) ?? '' },
    { header: 'Subject', accessor: (a: Asset) => certSubject(a) ?? '' },
    { header: 'SANs', accessor: (a: Asset) => certSans(a).join(';') },
    {
      header: 'Valid From',
      accessor: (a: Asset) => certNotBefore(a)?.toISOString() ?? '',
    },
    { header: 'Valid To', accessor: (a: Asset) => certNotAfter(a)?.toISOString() ?? '' },
    {
      header: 'Days Left',
      accessor: (a: Asset) => {
        const days = getDaysUntilExpiry(a)
        return days !== null ? days : ''
      },
    },
    { header: 'Validity', accessor: (a: Asset) => getCertStatus(a) },
    { header: 'Risk Score', accessor: (a: Asset) => a.riskScore },
    { header: 'Findings', accessor: (a: Asset) => a.findingCount },
  ],

  includeGroupSelect: false,
}
