'use client'

/**
 * Key facts: the few answers a reader wants first for an asset of a given
 * class, right under the header (research 129 §3.2). A subdomain: what it
 * resolves to, via which CNAME, who hosts it, which web server, TLS and
 * stack, its DNS records. A certificate: subject, names covered, issuer,
 * validity, key. Rows come from registry keys, so labels are the registry's
 * (en/vi); a row renders only when the asset has a value, lists are complete
 * (no "+N"), and every value goes through the shared `PropertyValue`.
 * The full property list stays below under "All properties".
 */

import * as React from 'react'
import { Radar } from 'lucide-react'
import { DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { classOfAsset } from '@/features/asset-types/lib/asset-registry'
import {
  canonicalPropertyKey,
  propertyDefinition,
  propertyKeysOf,
  propertyLabel,
} from '@/features/asset-types/lib/property-schema'
import type { AssetClass } from '@/features/asset-types/registry.generated'
import { technologies, tlsFacts } from '../lib/service-facts'
import type { Asset } from '../types/asset.types'
import { PropertyValue, hasPropertyValue, isWideValue } from './property-value'
import { TechChips } from './service-cells/tech-chips'
import { TlsSummary } from './service-cells/tls-summary'
import { ChipRow } from './service-cells/fact-chip'
import { cellsForType } from './service-cells/cells-for-type'
import { NotCollectedNote } from './service-cells/not-collected'
import { missingSurfaceFacts } from './service-cells/surface-facts'

type Props = Record<string, unknown> | undefined

/** The value of a registry key, or of a synonym an older row still holds. */
export function factValue(props: Props, key: string): unknown {
  if (!props) return undefined
  if (hasPropertyValue(props[key])) return props[key]
  for (const s of propertyDefinition(key)?.synonyms ?? []) {
    if (hasPropertyValue(props[s])) return props[s]
  }
  return undefined
}

type T = ReturnType<typeof useTranslation>['t']

/**
 * One row: a registry key (label and format from the registry), or a
 * composite with its own label and renderer.
 */
type Row =
  | string
  | {
      id: string
      label: (t: T, locale: string) => string
      /** The keys the row reads; it renders when any has a value. */
      keys: string[]
      /** Renders when true, for a fact that is not a property. */
      present?: (asset: Asset) => boolean
      render?: (asset: Asset, t: T) => React.ReactNode
      wide?: boolean
    }

const joined = (asset: Asset, keys: string[], sep = ' · ') =>
  keys
    .map((k) => factValue(asset.metadata, k))
    .filter((v) => hasPropertyValue(v))
    .map(String)
    .join(sep)

const RESOLVES_TO: Row = {
  id: 'resolves_to',
  label: (t) => t('assets.keyFacts.resolvesTo', 'Resolves to'),
  keys: ['ip_addresses'],
  render: (a) => <PropertyValue value={factValue(a.metadata, 'ip_addresses')} format="ip" />,
}

const HOSTING: Row = {
  id: 'hosting',
  label: (t) => t('assets.keyFacts.hosting', 'Hosting'),
  keys: ['asn', 'asn_org', 'isp'],
  render: (a) => joined(a, ['asn', 'asn_org']) || joined(a, ['isp']),
}

const NETWORK_OWNER: Row = {
  id: 'network_owner',
  label: (t) => t('assets.keyFacts.networkOwner', 'Network owner'),
  keys: ['asn', 'asn_org', 'isp'],
  render: (a) => joined(a, ['asn', 'asn_org', 'isp']),
}

const TLS: Row = {
  id: 'tls',
  label: (t) => t('assets.keyFacts.tls', 'TLS'),
  keys: ['has_tls', 'tls_version', 'tls', 'certificate'],
  render: (a) => {
    const facts = tlsFacts(a)
    const version = joined(a, ['tls_version'])
    if (facts.kind === 'not_collected') return version
    return (
      <ChipRow>
        <TlsSummary facts={facts} detail />
        {version && <span className="text-sm">{version}</span>}
      </ChipRow>
    )
  },
}

const TECH: Row = {
  id: 'technologies',
  label: (t) => t('assets.technologies.title', 'Technologies'),
  keys: [],
  present: (a) => (a.technologies?.length ?? 0) > 0,
  render: (a) => (
    <ChipRow>
      <TechChips technologies={technologies(a)} max={Infinity} />
    </ChipRow>
  ),
}

const LOCATION: Row = {
  id: 'location',
  label: (t) => t('assets.keyFacts.location', 'Location'),
  keys: ['city', 'country'],
  render: (a) => joined(a, ['city', 'country'], ', '),
}

const ENDPOINT: Row = {
  id: 'endpoint',
  label: (t) => t('assets.keyFacts.endpoint', 'Endpoint'),
  keys: ['port'],
  render: (a) => {
    const port = factValue(a.metadata, 'port')
    const proto = factValue(a.metadata, 'protocol') ?? factValue(a.metadata, 'transport')
    return <span className="font-mono text-xs">{proto ? `${port}/${proto}` : String(port)}</span>
  },
}

const PRODUCT: Row = {
  id: 'product',
  label: (t) => t('assets.keyFacts.product', 'Product'),
  keys: ['product'],
  render: (a) => joined(a, ['product', 'version'], ' '),
}

const HTTP: Row = {
  id: 'http',
  label: (t) => t('assets.keyFacts.http', 'HTTP response'),
  keys: ['status_code', 'title'],
  render: (a) => joined(a, ['status_code', 'title']),
}

const ISSUER: Row = {
  id: 'issuer',
  label: (t) => t('assets.keyFacts.issuer', 'Issuer'),
  keys: ['issuer_cn', 'issuer_org'],
  render: (a) => joined(a, ['issuer_cn', 'issuer_org']),
}

const KEY: Row = {
  id: 'key',
  label: (t) => t('assets.keyFacts.key', 'Key'),
  keys: ['key_algorithm', 'key_size'],
  render: (a) => joined(a, ['key_algorithm', 'key_size'], ' '),
}

const OS: Row = {
  id: 'os',
  label: (t) => t('assets.keyFacts.os', 'Operating system'),
  keys: ['os_name', 'os_version', 'os_family'],
  render: (a) => joined(a, ['os_name', 'os_version'], ' ') || joined(a, ['os_family']),
}

const HARDWARE: Row = {
  id: 'hardware',
  label: (t) => t('assets.keyFacts.hardware', 'Hardware'),
  keys: ['cpu_count', 'memory_gb', 'architecture'],
  render: (a, t) => {
    const v = (n: string) => factValue(a.metadata, n)
    return [
      hasPropertyValue(v('cpu_count')) &&
        t('assets.keyFacts.cpus', '{n} CPU', { n: String(v('cpu_count')) }),
      hasPropertyValue(v('memory_gb')) &&
        t('assets.keyFacts.memoryGb', '{n} GB', { n: String(v('memory_gb')) }),
      hasPropertyValue(v('architecture')) && String(v('architecture')),
    ]
      .filter(Boolean)
      .join(' · ')
  },
}

const LOCATION_CLOUD: Row = {
  id: 'cloud_location',
  label: (t) => t('assets.keyFacts.cloudLocation', 'Provider and region'),
  keys: ['provider', 'region', 'zone'],
  render: (a) => joined(a, ['provider', 'region', 'zone']),
}

const ENCRYPTION: Row = {
  id: 'encryption',
  label: (_t, locale) => propertyLabel('is_encrypted', locale),
  keys: ['is_encrypted', 'encryption_type'],
  render: (a) => {
    const on = factValue(a.metadata, 'is_encrypted')
    const kind = factValue(a.metadata, 'encryption_type')
    return (
      <>
        <PropertyValue value={on} />
        {hasPropertyValue(kind) && <span className="text-muted-foreground"> · {String(kind)}</span>}
      </>
    )
  },
}

/** Key facts per class, in reading order. */
const ROWS: Partial<Record<AssetClass, Row[]>> = {
  domain: [
    RESOLVES_TO,
    'cname_target',
    HOSTING,
    'server',
    TLS,
    TECH,
    'dns_records',
    'registrar',
    'expires_at',
    'nameservers',
  ],
  ip_address: [NETWORK_OWNER, 'hostname', LOCATION, 'ports', 'is_private'],
  service: [ENDPOINT, PRODUCT, 'cpe', TLS, HTTP, 'server', TECH, 'banner'],
  web_endpoint: ['url', HTTP, 'server', TLS, TECH],
  application: ['url', HTTP, 'server', TLS, TECH],
  certificate: [
    'subject_cn',
    'sans',
    ISSUER,
    'not_before',
    'not_after',
    KEY,
    'signature_algorithm',
    'fingerprint_sha256',
    'is_self_signed',
  ],
  host: [
    OS,
    'fqdn',
    'ip_addresses',
    'mac_addresses',
    HARDWARE,
    'hypervisor',
    'kernel_version',
    'has_edr',
  ],
  code_repo: ['visibility', 'language', 'default_branch', 'last_commit_at', 'canonical_url'],
  data_store: [
    LOCATION_CLOUD,
    'account_id',
    'public_access',
    ENCRYPTION,
    'has_versioning',
    'has_logging',
    'arn',
  ],
  cloud_account: ['provider', 'account_id', 'account_name', 'organization_id', 'has_mfa'],
}

/** How many schema keys a class without its own rows shows. */
const DEFAULT_ROWS = 6

function rowsFor(asset: Asset): Row[] {
  const cls = classOfAsset(undefined, asset.type, asset.subType)
  const rows = ROWS[cls]
  if (rows) return rows
  return propertyKeysOf(asset.type, asset.subType)
    .filter((k) => hasPropertyValue(factValue(asset.metadata, k)))
    .slice(0, DEFAULT_ROWS)
}

export interface KeyFact {
  id: string
  label: string
  node: React.ReactNode
  wide: boolean
}

/** The key facts this asset has a value for, in order. */
export function useKeyFacts(asset: Asset): KeyFact[] {
  const { t, locale } = useTranslation()
  return React.useMemo(() => {
    const out: KeyFact[] = []
    for (const row of rowsFor(asset)) {
      if (typeof row === 'string') {
        const key = canonicalPropertyKey(row)
        const value = factValue(asset.metadata, key)
        if (!hasPropertyValue(value)) continue
        out.push({
          id: key,
          label: propertyLabel(key, locale),
          node: <PropertyValue value={value} format={propertyDefinition(key)?.format} />,
          wide: isWideValue(value),
        })
        continue
      }
      if (!(
        row.present?.(asset) ?? row.keys.some((k) => hasPropertyValue(factValue(asset.metadata, k)))
      ))
        continue
      const node = row.render ? row.render(asset, t) : null
      if (node === '' || node === null || node === undefined) continue
      out.push({ id: row.id, label: row.label(t, locale), node, wide: !!row.wide })
    }
    return out
  }, [asset, t, locale])
}

/** Whether the asset has at least one key fact (without rendering them). */
export function hasKeyFacts(asset: Asset): boolean {
  const rows = rowsFor(asset)
  if (rows.some((r) => typeof r !== 'string' && r.present?.(asset))) return true
  return rows
    .flatMap((r) => (typeof r === 'string' ? [r] : r.keys))
    .some((k) => hasPropertyValue(factValue(asset.metadata, k)))
}

/** The key facts of an asset as a label/value grid; nothing when it has none. */
export function KeyFactsGrid({ facts }: { facts: KeyFact[] }) {
  if (facts.length === 0) return null
  return (
    <DetailFieldGrid>
      {facts.map((f) => (
        <DetailField key={f.id} label={f.label} full={f.wide}>
          {f.node}
        </DetailField>
      ))}
    </DetailFieldGrid>
  )
}

/**
 * The drawer's "Key facts" section: the facts, then, for an external-surface
 * type, one muted "Not collected yet: …" line naming what no scan recorded.
 */
export function KeyFactsSection({ asset }: { asset: Asset }) {
  const { t } = useTranslation()
  const facts = useKeyFacts(asset)
  const missing = cellsForType(asset.type, asset.subType) ? missingSurfaceFacts(asset) : []
  if (facts.length === 0 && missing.length === 0) return null
  return (
    <DetailSection title={t('assets.keyFacts.title', 'Key facts')} icon={Radar}>
      <KeyFactsGrid facts={facts} />
      <NotCollectedNote items={missing} />
    </DetailSection>
  )
}
