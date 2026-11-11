'use client'

/** The cells of the IP addresses tab (see lib/ip-columns). Every value is text, never HTML. */

import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import {
  IP_NAMES_SHOWN,
  IP_PORTS_SHOWN,
  formatPort,
  networkFilter,
  shownWithMore,
} from '../../lib/ip-columns'
import type { Asset } from '../../types/asset.types'

const CHIP = 'inline-flex max-w-40 items-center truncate rounded border bg-muted/40 px-1.5 text-xs'

/** The network of an address; a click filters the list to that network. */
export function NetworkCell({
  ip,
  onFilter,
}: {
  ip: Asset['ip']
  onFilter?: (network: string) => void
}) {
  const { t } = useTranslation()
  const network = networkFilter(ip?.network)
  if (!network) return <span className="text-muted-foreground">—</span>
  const label = toDisplayText(network, 64)
  if (!onFilter) {
    return (
      <span className="font-mono text-xs" dir="ltr">
        {label}
      </span>
    )
  }
  return (
    <button
      type="button"
      data-testid="ip-network-cell"
      className="rounded font-mono text-xs underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      dir="ltr"
      title={t('assets.ip.filterNetwork', 'Show only {network}', { network: label })}
      onClick={(e) => {
        e.stopPropagation()
        onFilter(network)
      }}
    >
      {label}
    </button>
  )
}

/** The names that resolve to an address: up to three, then "+N". */
export function NamesCell({ ip }: { ip: Asset['ip'] }) {
  const { t } = useTranslation()
  if (!ip || ip.names.length === 0) return <span className="text-muted-foreground">—</span>
  const { shown, more } = shownWithMore(ip.names, ip.namesTotal, IP_NAMES_SHOWN)
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1" data-testid="ip-names-cell">
      {shown.map((n) => (
        <span key={n} className={CHIP} title={toDisplayText(n, 253)}>
          {toDisplayText(n, 48)}
        </span>
      ))}
      {more > 0 && (
        <span className="text-xs text-muted-foreground">
          {t('assets.ip.more', '+{count}', { count: more })}
        </span>
      )}
    </div>
  )
}

/** The open ports of an address: `443/tcp https`, up to five, then "+N". */
export function PortsCell({ ip }: { ip: Asset['ip'] }) {
  const { t } = useTranslation()
  if (!ip || ip.ports.length === 0) return <span className="text-muted-foreground">—</span>
  const { shown, more } = shownWithMore(ip.ports, ip.portsTotal, IP_PORTS_SHOWN)
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1" data-testid="ip-ports-cell">
      {shown.map((p) => (
        <span key={`${p.port}/${p.transport ?? ''}`} className={`${CHIP} font-mono`} dir="ltr">
          {toDisplayText(formatPort(p), 48)}
        </span>
      ))}
      {more > 0 && (
        <span className="text-xs text-muted-foreground">
          {t('assets.ip.more', '+{count}', { count: more })}
        </span>
      )}
    </div>
  )
}
