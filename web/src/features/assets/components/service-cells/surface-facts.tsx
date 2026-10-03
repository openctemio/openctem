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
import { ChipMono, ChipRow, FactChip, UnknownChip } from './fact-chip'
import { HttpStatusChip } from './http-status-chip'
import { OverflowChips } from './overflow-chips'
import { TechChips } from './tech-chips'
import { CertExpiryChip, TlsSummary } from './tls-summary'

/** The port as "443/https", or null when no port was recorded. */
export function PortChip({ asset }: { asset: Asset }) {
  const port = servicePort(asset)
  if (port === null) return <UnknownChip>Port unknown</UnknownChip>
  const proto = serviceProtocol(asset)
  return (
    <FactChip tone="muted">
      <span>Port</span>
      <ChipMono>{proto ? `${port}/${proto}` : port}</ChipMono>
    </FactChip>
  )
}

/** Open ports of an IP: the first few, then "+N". */
export function OpenPortChips({ asset, max = 4 }: { asset: Asset; max?: number }) {
  const ports = openPorts(asset)
  if (ports === null) return <UnknownChip>Ports not collected</UnknownChip>
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

const RENDER: Record<SurfaceCell, (asset: Asset) => ReactNode> = {
  status: (a) => <HttpStatusChip status={httpStatusCode(a)} chain={redirectChain(a)} />,
  port: (a) => <PortChip asset={a} />,
  product: (a) => <ProductChip asset={a} />,
  ip: (a) => <OverflowChips label="IP" values={ipAddresses(a)} />,
  cname: (a) => <OverflowChips label="CNAME" values={cnames(a)} />,
  asn: (a) => {
    const { asn, org } = asnInfo(a)
    if (!asn) return null
    return (
      <FactChip tone="muted" title={org}>
        <ChipMono>{asn}</ChipMono>
        {org && <span className="max-w-[140px] truncate">{org}</span>}
      </FactChip>
    )
  },
  ports: (a) => <OpenPortChips asset={a} />,
  tech: (a) => <TechChips technologies={technologies(a)} max={2} />,
  tls: (a) => <TlsSummary facts={tlsFacts(a)} detail={false} />,
  cert: (a) => {
    const cert = recordedCertificate(a)
    return cert ? <CertExpiryChip cert={cert} /> : <UnknownChip>Expiry unknown</UnknownChip>
  },
}

/**
 * The external-surface facts of one asset as one chip row, chosen by
 * `cellsForType`. Renders nothing for a type outside the external surface.
 * Every value is scanner-supplied text and is rendered as text.
 */
export function SurfaceFacts({ asset, className }: { asset: Asset; className?: string }) {
  const cells = cellsForType(asset.type, asset.subType)
  if (!cells) return null
  return (
    <ChipRow className={className}>
      {cells.map((cell) => (
        <RenderCell key={cell} cell={cell} asset={asset} />
      ))}
    </ChipRow>
  )
}

function RenderCell({ cell, asset }: { cell: SurfaceCell; asset: Asset }) {
  return <>{RENDER[cell](asset)}</>
}
