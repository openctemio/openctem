import type { ReactNode } from 'react'
import type { Asset } from '../../types'
import {
  asnInfo,
  cnames,
  formatPort,
  httpStatusCode,
  ipAddresses,
  openPorts,
  recordedCertificate,
  redirectChain,
  serviceName,
  servicePort,
  serviceProduct,
  serviceProtocol,
  serviceVersion,
  technologies,
  tlsFacts,
} from '../../lib/service-facts'
import { cellsForType, type SurfaceCell } from './cells-for-type'
import { ChipMono, ChipRow, FactChip } from './fact-chip'
import { HttpStatusChip } from './http-status-chip'
import { EmptyCell, NotCollectedNote } from './not-collected'
import { OverflowChips } from './overflow-chips'
import { TechChips } from './tech-chips'
import { CertExpiryChip, TlsSummary, tlsNotCollected } from './tls-summary'

/** The port as "443/https"; `fallback` (nothing by default) when none was recorded. */
export function PortChip({ asset, fallback = null }: { asset: Asset; fallback?: ReactNode }) {
  const port = servicePort(asset)
  if (port === null) return <>{fallback}</>
  const proto = serviceProtocol(asset)
  return (
    <FactChip tone="muted">
      <span>Port</span>
      <ChipMono>{proto ? `${port}/${proto}` : port}</ChipMono>
    </FactChip>
  )
}

/**
 * Open ports of an IP: the first few, then "+N". "No open ports" (a scan
 * found none) is shown; no port scan at all renders `fallback` (nothing by
 * default).
 */
export function OpenPortChips({
  asset,
  max = 4,
  fallback = null,
}: {
  asset: Asset
  max?: number
  fallback?: ReactNode
}) {
  const ports = openPorts(asset)
  if (ports === null) return <>{fallback}</>
  if (ports.length === 0) return <FactChip tone="muted">No open ports</FactChip>
  const shown = ports.slice(0, max)
  const rest = ports.length - shown.length
  return (
    <>
      {shown.map((p) => (
        <FactChip key={formatPort(p)} tone="muted" title={p.service}>
          <ChipMono>{formatPort(p)}</ChipMono>
        </FactChip>
      ))}
      {rest > 0 && (
        <FactChip
          tone="muted"
          className="tabular-nums"
          title={ports.slice(max).map(formatPort).join(', ')}
        >
          +{rest}
        </FactChip>
      )}
    </>
  )
}

/** The product and version a service scan recorded ("OpenSSH 9.6p1"). */
export function ProductChip({ asset }: { asset: Asset }) {
  const product = serviceProduct(asset) ?? serviceName(asset)
  const version = serviceVersion(asset)
  if (!product && !version) return null
  return (
    <FactChip tone="neutral">
      {product && <span className="truncate">{product}</span>}
      {version && <span className="text-muted-foreground">{version}</span>}
    </FactChip>
  )
}

interface CellSpec {
  /** Whether the cell has anything to show for this asset. */
  known: (a: Asset) => boolean
  render: (a: Asset) => ReactNode
  /**
   * What the drawer's "Not collected yet" line names when this fact is
   * missing, or null. Optional facts (CNAME, ASN, product) are not gaps.
   */
  missing?: (a: Asset) => string | null
}

const SPECS: Record<SurfaceCell, CellSpec> = {
  status: {
    known: (a) => httpStatusCode(a) !== null,
    render: (a) => <HttpStatusChip status={httpStatusCode(a)} chain={redirectChain(a)} />,
    missing: (a) => (httpStatusCode(a) === null ? 'HTTP status' : null),
  },
  port: {
    known: (a) => servicePort(a) !== null,
    render: (a) => <PortChip asset={a} />,
    missing: (a) => (servicePort(a) === null ? 'port' : null),
  },
  product: {
    known: (a) => !!(serviceProduct(a) ?? serviceName(a) ?? serviceVersion(a)),
    render: (a) => <ProductChip asset={a} />,
  },
  ip: {
    known: (a) => ipAddresses(a).length > 0,
    render: (a) => <OverflowChips label="IP" values={ipAddresses(a)} />,
  },
  cname: {
    known: (a) => cnames(a).length > 0,
    render: (a) => <OverflowChips label="CNAME" values={cnames(a)} />,
  },
  // The data cannot tell "never resolved" from "resolved to nothing": both
  // are an empty record list. It keeps its old meaning (not collected).
  dns: {
    known: (a) => cnames(a).length > 0 || ipAddresses(a).length > 0,
    render: (a) => (
      <>
        <OverflowChips label="CNAME" values={cnames(a)} />
        <OverflowChips label="IP" values={ipAddresses(a)} />
      </>
    ),
    missing: (a) => (cnames(a).length === 0 && ipAddresses(a).length === 0 ? 'DNS records' : null),
  },
  asn: {
    known: (a) => !!asnInfo(a).asn,
    render: (a) => {
      const { asn, org } = asnInfo(a)
      return (
        <FactChip tone="muted" title={org}>
          <ChipMono>{asn}</ChipMono>
          {org && <span className="max-w-[140px] truncate">{org}</span>}
        </FactChip>
      )
    },
  },
  ports: {
    known: (a) => openPorts(a) !== null,
    render: (a) => <OpenPortChips asset={a} />,
    missing: (a) => (openPorts(a) === null ? 'open ports' : null),
  },
  tech: {
    known: (a) => technologies(a) !== null,
    render: (a) => <TechChips technologies={technologies(a)} max={2} />,
    missing: (a) => (technologies(a) === null ? 'technologies' : null),
  },
  tls: {
    known: (a) => tlsFacts(a).kind !== 'not_collected',
    render: (a) => <TlsSummary facts={tlsFacts(a)} detail={false} />,
    missing: (a) => tlsNotCollected(tlsFacts(a)),
  },
  cert: {
    known: (a) => {
      const c = recordedCertificate(a)
      return c !== null && c.status !== 'unknown'
    },
    render: (a) => {
      const c = recordedCertificate(a)
      return c ? <CertExpiryChip cert={c} /> : null
    },
    missing: (a) => {
      const c = recordedCertificate(a)
      return c === null || c.status === 'unknown' ? 'certificate expiry' : null
    },
  },
}

/** The external-surface facts no scan has recorded for this asset, in cell order. */
export function missingSurfaceFacts(asset: Asset): string[] {
  const cells = cellsForType(asset.type, asset.subType) ?? []
  const out: string[] = []
  for (const cell of cells) {
    const label = SPECS[cell].missing?.(asset)
    if (label && !out.includes(label)) out.push(label)
  }
  return out
}

/** Whether `SurfaceFacts` has at least one known fact to show. */
export function hasSurfaceFacts(asset: Asset): boolean {
  const cells = cellsForType(asset.type, asset.subType) ?? []
  return cells.some((cell) => SPECS[cell].known(asset))
}

/**
 * The external-surface facts of one asset as one chip row, chosen by
 * `cellsForType`. Only known facts are shown: a fact nothing collected
 * renders nothing, and a row with no known fact at all renders `empty`
 * (the muted `—` by default). Renders nothing for a type outside the
 * external surface. Every value is scanner-supplied text, rendered as text.
 */
export function SurfaceFacts({
  asset,
  className,
  empty = <EmptyCell />,
}: {
  asset: Asset
  className?: string
  empty?: ReactNode
}) {
  const cells = cellsForType(asset.type, asset.subType)
  if (!cells) return null
  const known = cells.filter((cell) => SPECS[cell].known(asset))
  if (known.length === 0) return <>{empty}</>
  return (
    <ChipRow className={className}>
      {known.map((cell) => (
        <RenderCell key={cell} cell={cell} asset={asset} />
      ))}
    </ChipRow>
  )
}

/**
 * The drawer's facts block: the known facts, then one muted "Not collected
 * yet: …" line naming every missing one (only when something is missing).
 */
export function SurfaceFactsDetail({ asset }: { asset: Asset }) {
  const missing = missingSurfaceFacts(asset)
  return (
    <div className="space-y-2">
      <SurfaceFacts asset={asset} empty={null} />
      <NotCollectedNote items={missing} />
    </div>
  )
}

function RenderCell({ cell, asset }: { cell: SurfaceCell; asset: Asset }) {
  return <>{SPECS[cell].render(asset)}</>
}
