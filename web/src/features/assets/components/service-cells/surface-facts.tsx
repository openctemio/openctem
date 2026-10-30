import { useId, type ReactNode } from 'react'
import { EdgeLabel } from '@/features/scope/components/edge-label'
import { useTranslation } from '@/context/i18n-provider'
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
  formatTechnology,
  tlsFacts,
} from '../../lib/service-facts'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useFitCount } from '@/hooks/use-fit-count'
import { cellsForType, type SurfaceCell } from './cells-for-type'
import { ChipMono, ChipRow, FactChip } from './fact-chip'
import { HttpStatusChip } from './http-status-chip'
import { EmptyCell, NotCollectedNote } from './not-collected'
import { MoreChip } from './more-chip'
import { OverflowChips } from './overflow-chips'
import { TechChips } from './tech-chips'
import { CertExpiryChip, TlsSummary, tlsNotCollected } from './tls-summary'

/** The port as "443/https"; `fallback` (nothing by default) when none was recorded. */
export function PortChip({ asset, fallback = null }: { asset: Asset; fallback?: ReactNode }) {
  const { t } = useTranslation()
  const port = servicePort(asset)
  if (port === null) return <>{fallback}</>
  const proto = serviceProtocol(asset)
  return (
    <FactChip tone="muted">
      <span>{t('assets.facts.port', 'Port')}</span>
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
  const { t } = useTranslation()
  const ports = openPorts(asset)
  if (ports === null) return <>{fallback}</>
  if (ports.length === 0)
    return <FactChip tone="muted">{t('assets.facts.noOpenPorts', 'No open ports')}</FactChip>
  const shown = ports.slice(0, max)
  return (
    <>
      {shown.map((p) => (
        <FactChip key={formatPort(p)} tone="muted" title={p.service}>
          <ChipMono>{formatPort(p)}</ChipMono>
        </FactChip>
      ))}
      <MoreChip
        label={t('assets.facts.ports', 'ports')}
        values={ports.slice(shown.length).map(formatPort)}
      />
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

/**
 * The edge label: "Behind Cloudflare" on a name or service served through a
 * provider, "Cloudflare edge" on the provider's own address (with "Add to out
 * of scope"). The API computes `edge` (research/259); one shared component
 * for assets and scope entries.
 */
export function EdgeChip({ asset }: { asset: Pick<Asset, 'edge' | 'triage'> }) {
  if (!asset.edge) return null
  return <EdgeLabel edge={asset.edge} excluded={asset.triage?.scanBlockedBy === 'excluded'} />
}

interface CellSpec {
  /** Whether the cell has anything to show for this asset. */
  known: (a: Asset) => boolean
  /** `all`: a detail view, every value is listed (no "+N"). */
  render: (a: Asset, all: boolean) => ReactNode
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
  edge: {
    known: (a) => !!a.edge,
    render: (a) => <EdgeChip asset={a} />,
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
    render: (a, all) => (
      <OverflowChips label="IP" values={ipAddresses(a)} max={all ? Infinity : 1} />
    ),
  },
  cname: {
    known: (a) => cnames(a).length > 0,
    render: (a, all) => <OverflowChips label="CNAME" values={cnames(a)} max={all ? Infinity : 1} />,
  },
  // The data cannot tell "never resolved" from "resolved to nothing": both
  // are an empty record list. It keeps its old meaning (not collected).
  dns: {
    known: (a) => cnames(a).length > 0 || ipAddresses(a).length > 0,
    render: (a, all) => (
      <>
        <OverflowChips label="CNAME" values={cnames(a)} max={all ? Infinity : 1} />
        <OverflowChips label="IP" values={ipAddresses(a)} max={all ? Infinity : 1} />
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
    render: (a, all) => <OpenPortChips asset={a} max={all ? Infinity : 4} />,
    missing: (a) => (openPorts(a) === null ? 'open ports' : null),
  },
  tech: {
    known: (a) => technologies(a) !== null,
    render: (a, all) => <TechChips technologies={technologies(a)} max={all ? Infinity : 2} />,
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
  all = false,
}: {
  asset: Asset
  className?: string
  empty?: ReactNode
  /** A detail view: list every value instead of "+N". */
  all?: boolean
}) {
  const cells = cellsForType(asset.type, asset.subType)
  if (!cells) return null
  const known = cells.filter((cell) => SPECS[cell].known(asset))
  if (known.length === 0) return <>{empty}</>
  return (
    <ChipRow className={className}>
      {known.map((cell) => (
        <RenderCell key={cell} cell={cell} asset={asset} all={all} />
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
      <SurfaceFacts asset={asset} empty={null} all />
      <NotCollectedNote items={missing} />
    </div>
  )
}

function RenderCell({ cell, asset, all }: { cell: SurfaceCell; asset: Asset; all: boolean }) {
  return <>{SPECS[cell].render(asset, all)}</>
}

/** One fact of the compact line, with the order it is shown in. */
interface FactAtom {
  key: string
  rank: number
  node: ReactNode
}

/** Status first, then the port, then what runs there, then where it lives. */
const ATOM_RANK: Record<SurfaceCell, number> = {
  status: 0,
  port: 1,
  ports: 1,
  edge: 2,
  tech: 3,
  product: 3,
  cert: 4,
  ip: 5,
  dns: 5,
  cname: 6,
  tls: 7,
  asn: 8,
}

function factAtoms(asset: Asset, cells: readonly SurfaceCell[]): FactAtom[] {
  const out: FactAtom[] = []
  const mono = (key: string, rank: number, v: string, label?: string) =>
    out.push({
      key,
      rank,
      node: (
        <FactChip tone="muted">
          {label && <span>{label}</span>}
          {/* A long name (an IPv6 address, a CNAME) ends in "…" inside its
              chip; the popover lists it whole. */}
          <span className="min-w-0 max-w-[10rem] truncate font-mono text-xs">{v}</span>
        </FactChip>
      ),
    })
  for (const cell of cells) {
    if (!SPECS[cell].known(asset)) continue
    const rank = ATOM_RANK[cell]
    switch (cell) {
      case 'status':
        out.push({
          key: 'status',
          rank,
          node: (
            <HttpStatusChip status={httpStatusCode(asset)} chain={redirectChain(asset)} compact />
          ),
        })
        break
      case 'port': {
        const port = servicePort(asset)
        const proto = serviceProtocol(asset)
        if (port !== null) mono('port', rank, proto ? `${port}/${proto}` : String(port))
        break
      }
      case 'ports':
        for (const p of openPorts(asset) ?? []) mono(`ports:${formatPort(p)}`, rank, formatPort(p))
        break
      case 'ip':
        for (const ip of ipAddresses(asset)) mono(`ip:${ip}`, rank, ip, 'IP')
        break
      case 'cname':
        for (const c of cnames(asset)) mono(`cname:${c}`, rank, c, 'CNAME')
        break
      case 'dns':
        for (const ip of ipAddresses(asset)) mono(`ip:${ip}`, ATOM_RANK.ip, ip, 'IP')
        for (const c of cnames(asset)) mono(`cname:${c}`, ATOM_RANK.cname, c, 'CNAME')
        break
      case 'tech':
        for (const tech of technologies(asset) ?? [])
          out.push({
            key: `tech:${tech.name}`,
            rank,
            node: (
              <FactChip tone="neutral">
                <span className="max-w-[9rem] truncate">{formatTechnology(tech)}</span>
              </FactChip>
            ),
          })
        break
      default:
        out.push({ key: cell, rank, node: SPECS[cell].render(asset, false) })
    }
  }
  // Stable: equal ranks keep the type's own order.
  return out
    .map((a, i) => ({ a, i }))
    .sort((x, y) => x.a.rank - y.a.rank || x.i - y.i)
    .map((x) => x.a)
}

const FACT_GAP = 4 // gap-1
const MORE_WIDTH = 40 // the "+N" chip, up to two digits

/**
 * The list's service facts on ONE line (research/266) that always fits its
 * cell: the facts in a fixed order (status as its code, the port, the edge
 * provider, what runs there, where it lives), as many WHOLE chips as the
 * cell holds (measured, `useFitCount`), at most `max`; the rest fold into
 * "+N", a button that opens every fact in a popover (click, tap or
 * keyboard). No chip is ever cut by the cell's edge, every row has the same
 * height, and only the status and edge chips have a tooltip.
 */
export function SurfaceFactsLine({ asset, max = 4 }: { asset: Asset; max?: number }) {
  const cells = cellsForType(asset.type, asset.subType)
  if (!cells) return null
  const atoms = factAtoms(asset, cells)
  if (atoms.length === 0) return <EmptyCell />
  return <FittedFacts asset={asset} atoms={atoms} max={max} />
}

function FittedFacts({ asset, atoms, max }: { asset: Asset; atoms: FactAtom[]; max: number }) {
  const { t } = useTranslation()
  const titleId = useId()
  const capped = atoms.slice(0, max)
  const { rowRef, fit } = useFitCount<HTMLDivElement>(
    capped.map((a) => a.key),
    { gap: FACT_GAP, more: MORE_WIDTH }
  )
  const shown = capped.slice(0, fit)
  const rest = atoms.length - shown.length
  return (
    <div
      ref={rowRef}
      data-testid="surface-facts-line"
      data-folded={rest > 0 ? rest : undefined}
      className="flex w-full min-w-0 flex-nowrap items-center gap-1 overflow-hidden"
    >
      {shown.map((a) => (
        <span key={a.key} data-fit-key={a.key} className="inline-flex shrink-0">
          {a.node}
        </span>
      ))}
      {rest > 0 && (
        <Popover>
          <PopoverTrigger asChild>
            <button
              type="button"
              data-slot="facts-more"
              onClick={(e) => e.stopPropagation()}
              aria-label={t('assets.facts.moreFacts', '{count} more facts', { count: rest })}
              className="shrink-0 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&>[data-slot=fact-chip]]:hover:bg-accent"
            >
              <FactChip tone="muted" className="tabular-nums">
                +{rest}
              </FactChip>
            </button>
          </PopoverTrigger>
          <PopoverContent
            align="start"
            className="w-[min(380px,calc(100vw-32px))] p-3"
            aria-labelledby={titleId}
            onClick={(e) => e.stopPropagation()}
          >
            <p id={titleId} className="mb-2 text-xs font-medium text-muted-foreground">
              {t('assets.facts.title', 'Service facts')}
            </p>
            <SurfaceFactsDetail asset={asset} />
          </PopoverContent>
        </Popover>
      )}
    </div>
  )
}
