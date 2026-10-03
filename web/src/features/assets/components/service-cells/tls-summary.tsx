import { Lock, LockOpen } from 'lucide-react'
import type { TlsCertificate, TlsFacts } from '../../lib/service-facts'
import { FactChip, UnknownChip } from './fact-chip'

function days(n: number): string {
  return `${n} ${n === 1 ? 'day' : 'days'}`
}

/** The expiry chip of a recorded certificate. */
export function CertExpiryChip({ cert }: { cert: TlsCertificate }) {
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
      return (
        <UnknownChip title="The certificate was recorded without an expiry date">
          Expiry unknown
        </UnknownChip>
      )
  }
}

export interface TlsSummaryProps {
  facts: TlsFacts
  /** Show issuer and SAN lines under the chip (the list cell does). */
  detail?: boolean
  /** Say "Certificate not collected" under a TLS chip (the drawer does). */
  explainMissing?: boolean
}

/**
 * TLS on a service in one cell: the certificate's expiry chip with issuer
 * and SAN under it, or one of three explicit states: "TLS" with the
 * certificate not collected, "No TLS" (served over plain HTTP) and "TLS not
 * collected" (nothing recorded). None of them is shown as healthy.
 */
export function TlsSummary({ facts, detail = true, explainMissing = false }: TlsSummaryProps) {
  switch (facts.kind) {
    case 'not_collected':
      return (
        <UnknownChip title="No probe recorded whether this service uses TLS">
          TLS not collected
        </UnknownChip>
      )
    case 'none':
      return (
        <FactChip tone="muted" title="A probe reached this service over plain HTTP">
          <LockOpen aria-hidden="true" />
          No TLS
        </FactChip>
      )
    case 'tls':
      return (
        <div className="min-w-0">
          <FactChip tone="muted" title="Served over TLS; the certificate was not collected">
            <Lock aria-hidden="true" />
            TLS
          </FactChip>
          {explainMissing && (
            <p className="mt-1 text-xs text-muted-foreground">Certificate not collected</p>
          )}
        </div>
      )
    case 'cert': {
      const { cert } = facts
      const [firstSan, ...moreSans] = cert.sans
      return (
        <div className="min-w-0">
          <CertExpiryChip cert={cert} />
          {detail && (
            <div className="mt-1 space-y-0.5 text-xs text-muted-foreground">
              <p className="truncate" title={cert.issuer}>
                {cert.issuer ?? 'Issuer unknown'}
              </p>
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
