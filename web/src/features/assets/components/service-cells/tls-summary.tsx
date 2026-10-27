import type { ReactNode } from 'react'
import { Lock, LockOpen } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import type { TlsCertificate, TlsFacts } from '../../lib/service-facts'
import { FactChip } from './fact-chip'

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
  const { t } = useTranslation()
  const days = (n: number) =>
    n === 1 ? t('assets.tls.dayOne', '1 day') : t('assets.tls.dayMany', '{n} days', { n })
  const title = cert.notAfter
    ? t('assets.tls.validUntil', 'Valid until {date}', { date: cert.notAfter.toLocaleDateString() })
    : undefined
  switch (cert.status) {
    case 'expired':
      return (
        <FactChip tone="destructive" title={title}>
          {cert.daysLeft === null
            ? t('assets.tls.expired', 'Expired')
            : t('assets.tls.expiredAgo', 'Expired {days} ago', { days: days(-cert.daysLeft) })}
        </FactChip>
      )
    case 'expiring':
      return (
        <FactChip tone="warning" title={title}>
          {cert.daysLeft === 0
            ? t('assets.tls.expiresToday', 'Expires today')
            : t('assets.tls.expiresIn', 'Expires in {days}', { days: days(cert.daysLeft ?? 0) })}
        </FactChip>
      )
    case 'valid':
      return (
        <FactChip tone="success" title={title}>
          {t('assets.tls.validLeft', 'Valid, {days} left', { days: days(cert.daysLeft ?? 0) })}
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
  const { t } = useTranslation()
  return (
    <FactChip tone="muted" title={title}>
      <Lock aria-hidden="true" />
      {t('assets.tls.chip', 'TLS')}
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
  const { t } = useTranslation()
  switch (facts.kind) {
    case 'not_collected':
      return <>{fallback}</>
    case 'none':
      return (
        <FactChip
          tone="muted"
          title={t('assets.tls.plainHttp', 'A probe reached this service over plain HTTP')}
        >
          <LockOpen aria-hidden="true" />
          {t('assets.tls.none', 'No TLS')}
        </FactChip>
      )
    case 'tls':
      return (
        <TlsChip
          title={t('assets.tls.noCert', 'Served over TLS; the certificate was not collected')}
        />
      )
    case 'cert': {
      const { cert } = facts
      const [firstSan, ...moreSans] = cert.sans
      return (
        <div className="min-w-0">
          <CertExpiryChip
            cert={cert}
            fallback={
              <TlsChip
                title={t(
                  'assets.tls.noExpiry',
                  'The certificate was recorded without an expiry date'
                )}
              />
            }
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
