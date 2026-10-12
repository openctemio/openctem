import type { ReactNode } from 'react'
import { Lock, LockOpen } from 'lucide-react'
import type { TlsCertificate, TlsFacts } from '../../lib/service-facts'
import { FactChip } from './fact-chip'

function days(n: number): string {
  return `${n} ${n === 1 ? 'day' : 'days'}`
}

/**
 * The expiry chip of a recorded certificate. A certificate recorded without
 * an expiry date renders `fallback` (nothing by default): its expiry is not
 * collected, and is never shown as valid.
 */
export function CertExpiryChip({
  cert,
  fallback = null,
}: {
  cert: TlsCertificate
  fallback?: ReactNode
}) {
  const title = cert.notAfter ? `Valid until ${cert.notAfter.toLocaleDateString()}` : undefined
  switch (cert.status) {
    case 'expired':
      return (
        <FactChip tone="destructive" title={title}>
          {cert.daysLeft === null ? 'Expired' : `Expired ${days(-cert.daysLeft)} ago`}
        </FactChip>
      )
    case 'expiring':
      return (
        <FactChip tone="warning" title={title}>
          {cert.daysLeft === 0 ? 'Expires today' : `Expires in ${days(cert.daysLeft ?? 0)}`}
        </FactChip>
      )
    case 'valid':
      return (
        <FactChip tone="success" title={title}>
          Valid · {days(cert.daysLeft ?? 0)} left
        </FactChip>
      )
    default:
      return <>{fallback}</>
  }
}

/**
 * What the drawer's "Not collected yet" line says about TLS, or null when
 * nothing is missing:
 *
 * - nothing recorded either way: "TLS";
 * - served over TLS, certificate not collected: "TLS certificate";
 * - a certificate recorded without an expiry date: "certificate expiry".
 */
export function tlsNotCollected(facts: TlsFacts): string | null {
  switch (facts.kind) {
    case 'not_collected':
      return 'TLS'
    case 'tls':
      return 'TLS certificate'
    case 'cert':
      return facts.cert.status === 'unknown' ? 'certificate expiry' : null
    default:
      return null
  }
}

function TlsChip({ title }: { title: string }) {
  return (
    <FactChip tone="muted" title={title}>
      <Lock aria-hidden="true" />
      TLS
    </FactChip>
  )
}

export interface TlsSummaryProps {
  facts: TlsFacts
  /** Show issuer and SAN lines under the chip (the list cell does). */
  detail?: boolean
  /** Rendered when nothing recorded TLS either way: nothing by default. */
  fallback?: ReactNode
}

/**
 * TLS on a service in one cell: the certificate's expiry chip with issuer
 * and SAN under it, "TLS" (served over TLS, certificate not collected) or
 * "No TLS" (a probe reached it over plain HTTP: a known negative, always
 * shown). When nothing was recorded it renders `fallback`; the drawer names
 * the gap with `tlsNotCollected`. None of them is shown as healthy.
 */
export function TlsSummary({ facts, detail = true, fallback = null }: TlsSummaryProps) {
  switch (facts.kind) {
    case 'not_collected':
      return <>{fallback}</>
    case 'none':
      return (
        <FactChip tone="muted" title="A probe reached this service over plain HTTP">
          <LockOpen aria-hidden="true" />
          No TLS
        </FactChip>
      )
    case 'tls':
      return <TlsChip title="Served over TLS; the certificate was not collected" />
    case 'cert': {
      const { cert } = facts
      const [firstSan, ...moreSans] = cert.sans
      return (
        <div className="min-w-0">
          <CertExpiryChip
            cert={cert}
            fallback={<TlsChip title="The certificate was recorded without an expiry date" />}
          />
          {detail && (cert.issuer || firstSan) && (
            <div className="mt-1 space-y-0.5 text-xs text-muted-foreground">
              {cert.issuer && (
                <p className="truncate" title={cert.issuer}>
                  {cert.issuer}
                </p>
              )}
              {firstSan && (
                <p className="truncate font-mono" title={cert.sans.join(', ')}>
                  {firstSan}
                  {moreSans.length > 0 && (
                    <span className="font-sans tabular-nums"> +{moreSans.length}</span>
                  )}
                </p>
              )}
            </div>
          )}
        </div>
      )
    }
  }
}
