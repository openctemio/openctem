'use client'

/**
 * EASM overview (RFC-036 §6.11): ownership of the external surface, what is
 * new since the CTEM cycle started, Certificate-Transparency freshness and
 * the most severe open external exposures. Every number comes from
 * GET /api/v1/easm/summary; nothing is computed from a page of rows.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useState } from 'react'
import Link from '@/components/link'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { EASMMonitoringCard } from './easm-monitoring-card'
import { EVENT_TYPE_CONFIG, type ExposureEventType } from '@/lib/api/exposure-types'
import { Skeleton } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  RelativeTime,
  SeverityBadge,
  type Severity,
} from '@/features/shared'
import { useEASMSummary } from '../hooks/use-easm-summary'

const EXPOSURE_TYPE_LABEL: Record<string, [string, string]> = {
  subdomain_discovered: ['easmReview.exposure.subdomainDiscovered', 'Subdomain seen in CT'],
  certificate_expiring: ['easmReview.exposure.certificateExpiring', 'Certificate expiring'],
  certificate_expired: ['easmReview.exposure.certificateExpired', 'Certificate expired'],
  dangling_cname: ['easmReview.exposure.danglingCname', 'Dangling CNAME'],
  dangling_ns: ['easmReview.exposure.danglingNs', 'Dangling delegation'],
  email_security_weak: ['easmReview.exposure.emailSecurityWeak', 'Weak email security'],
  subdomain_takeover: ['easmReview.exposure.subdomainTakeover', 'Subdomain takeover'],
  lookalike_domain: ['easmReview.exposure.lookalikeDomain', 'Lookalike domain'],
  third_party_script_added: ['easmReview.exposure.thirdPartyScriptAdded', 'New third-party script'],
  port_open: ['easmReview.exposure.portOpen', 'Open port'],
  service_detected: ['easmReview.exposure.serviceDetected', 'Exposed service'],
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'none']

/** The attribution review queue page. */
export const EASM_REVIEW_HREF = '/attack-surface/review'

/** The API's severity string as a known severity (unknown → info). */
export function toSeverity(s: string | undefined): Severity {
  return SEVERITIES.includes(s as Severity) ? (s as Severity) : 'info'
}

type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** The exposure type in words; without a translator the English text. */
export function exposureTypeLabel(type: string, t?: T): string {
  const known = EXPOSURE_TYPE_LABEL[type]
  if (known) return t ? t(known[0], known[1]) : known[1]
  return EVENT_TYPE_CONFIG[type as ExposureEventType]?.label ?? type.replace(/_/g, ' ')
}

function Row({
  label,
  value,
  hint,
}: {
  label: string
  value: React.ReactNode
  hint?: React.ReactNode
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-end tabular-nums">
        {value}
        {hint && <span className="ms-1 text-xs text-muted-foreground">{hint}</span>}
      </span>
    </div>
  )
}

export function EASMOverview() {
  const { t } = useTranslation()
  // Counts cover the attributed inventory unless the viewer asks for the
  // discovered assets too (research/124): discovery noise never inflates them.
  const [includeDiscovered, setIncludeDiscovered] = useState(false)
  const { summary, isLoading, error, mutate } = useEASMSummary(includeDiscovered)
  useSettleSignal(isLoading)

  if (error) {
    return (
      <div>
        <ErrorState
          title={t('easmReview.overview.errorTitle', 'the external attack surface')}
          error={error}
          onRetry={() => mutate()}
        />
      </div>
    )
  }

  const a = summary?.attribution
  const n = summary?.new
  const m = summary?.monitoring
  const risks = summary?.top_risks ?? []

  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('easmReview.overview.surface', 'External surface')}
          </CardTitle>
          <CardDescription>
            {t(
              'easmReview.overview.surfaceHint',
              'Who it belongs to, what is new, how fresh the watch is'
            )}
          </CardDescription>
          <div className="flex items-center gap-2 pt-1">
            <Switch
              id="easm-include-discovered"
              checked={includeDiscovered}
              onCheckedChange={setIncludeDiscovered}
            />
            <Label htmlFor="easm-include-discovered" className="text-xs font-normal">
              {t('easmReview.overview.includeDiscovered', 'Include discovered assets')}
            </Label>
          </div>
        </CardHeader>
        <CardContent className="divide-y">
          {isLoading || !summary ? (
            <div className="space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-5 w-full" />
              ))}
            </div>
          ) : (
            <>
              <div className="pb-2">
                <Row
                  label={t('easmReview.overview.total', 'Domains, subdomains, IPs, certificates')}
                  value={summary.surface?.total ?? 0}
                />
                <Row
                  label={t('easmReview.overview.confirmed', 'Confirmed ours')}
                  value={a?.confirmed ?? 0}
                />
                {(a?.discovered ?? 0) > 0 && (
                  <Row
                    label={t(
                      'easmReview.overview.discovered',
                      'Discovered, passive only until in scope'
                    )}
                    value={a?.discovered ?? 0}
                  />
                )}
                <Row
                  label={t('easmReview.overview.waiting', 'Found, not yet decided')}
                  value={(a?.needs_review ?? 0) + (a?.candidate ?? 0)}
                  hint={
                    (a?.needs_review ?? 0) + (a?.candidate ?? 0) > 0 ? (
                      <span className="inline-flex flex-wrap items-baseline justify-end gap-x-2">
                        {a?.review_oldest_since && (
                          <span>
                            {t('easmReview.overview.oldest', 'oldest')}{' '}
                            <RelativeTime date={a.review_oldest_since} className="text-xs" />
                          </span>
                        )}
                        <Link
                          href={EASM_REVIEW_HREF}
                          className="font-medium text-foreground underline underline-offset-2"
                        >
                          {t('easmReview.overview.suggestions', 'Review')}
                        </Link>
                      </span>
                    ) : undefined
                  }
                />
                {(a?.dependency ?? 0) + (a?.monitor_only ?? 0) > 0 && (
                  <Row
                    label={t('easmReview.overview.dependency', 'Dependency or monitor only')}
                    value={(a?.dependency ?? 0) + (a?.monitor_only ?? 0)}
                  />
                )}
              </div>
              <div className="py-2">
                <Row
                  label={t('easmReview.overview.new7', 'New in the last 7 days')}
                  value={n?.last_7_days ?? 0}
                />
                <Row
                  label={t('easmReview.overview.new30', 'New in the last 30 days')}
                  value={n?.last_30_days ?? 0}
                />
                <Row
                  label={t('easmReview.overview.newCycle', 'New since the CTEM cycle started')}
                  value={n?.since_cycle ?? '—'}
                  hint={
                    n?.since_cycle === undefined
                      ? t('easmReview.overview.noCycle', 'no cycle started')
                      : undefined
                  }
                />
              </div>
              <div className="pt-2">
                <Row
                  label={t('easmReview.overview.ctWatched', 'Domains watched in CT logs')}
                  value={m?.ct_domains_watched ?? 0}
                />
                {(m?.ct_failing ?? 0) > 0 && (
                  <Row
                    label={t('easmReview.overview.ctFailing', 'CT lookups failing')}
                    value={m?.ct_failing}
                  />
                )}
                <Row
                  label={t('easmReview.overview.ctOldest', 'Oldest CT check')}
                  value={m?.ct_oldest_success ? <RelativeTime date={m.ct_oldest_success} /> : '—'}
                  hint={
                    !m?.ct_oldest_success && (m?.ct_domains_watched ?? 0) > 0
                      ? t('easmReview.overview.notChecked', 'not checked yet')
                      : undefined
                  }
                />
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">
            {t('easmReview.overview.risks', 'Top external risks')}
          </CardTitle>
          <CardDescription className="flex flex-wrap gap-x-3">
            <span>
              {t('easmReview.overview.risksHint', 'Open external exposures, most severe first')}
            </span>
            {summary?.exposures?.open ? (
              <span>
                {t('easmReview.overview.openTotal', '{n} open in total', {
                  n: summary.exposures.open,
                })}
              </span>
            ) : null}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading || !summary ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-9 w-full" />
              ))}
            </div>
          ) : risks.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title={t('easmReview.overview.noRisks', 'No open external risks')}
              description={t(
                'easmReview.overview.noRisksHint',
                'Nothing of medium severity or above is open on the external surface.'
              )}
              card={false}
            />
          ) : (
            <ul
              className="divide-y"
              aria-label={t('easmReview.overview.risks', 'Top external risks')}
            >
              {risks.map((r) => (
                <li key={r.id} className="flex items-center gap-3 py-2 text-sm">
                  <SeverityBadge severity={toSeverity(r.severity)} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{r.title}</div>
                    <div className="flex min-w-0 gap-x-2 text-xs text-muted-foreground">
                      <span className="shrink-0">{exposureTypeLabel(r.type ?? '', t)}</span>
                      {r.asset_name && <span className="truncate">{r.asset_name}</span>}
                    </div>
                  </div>
                  {r.last_seen && <RelativeTime date={r.last_seen} className="text-xs" />}
                </li>
              ))}
            </ul>
          )}
          {risks.length > 0 && (
            <Link
              href="/exposures"
              className="mt-3 inline-flex items-center gap-1 text-sm text-primary hover:underline"
            >
              <ShieldAlert className="h-4 w-4" />
              {t('easmReview.overview.allExposures', 'All exposures')}
            </Link>
          )}
        </CardContent>
      </Card>
      <EASMMonitoringCard />
    </div>
  )
}
