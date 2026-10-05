'use client'

/**
 * EASM overview (RFC-036 §6.11): ownership of the external surface, what is
 * new since the CTEM cycle started, Certificate-Transparency freshness and
 * the most severe open external exposures. Every number comes from
 * GET /api/v1/easm/summary; nothing is computed from a page of rows.
 */

import Link from 'next/link'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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

const EXPOSURE_TYPE_LABEL: Record<string, string> = {
  subdomain_discovered: 'Subdomain seen in CT',
  certificate_expiring: 'Certificate expiring',
  certificate_expired: 'Certificate expired',
  dangling_cname: 'Dangling CNAME',
  dangling_ns: 'Dangling delegation',
  email_security_weak: 'Weak email security',
  subdomain_takeover: 'Subdomain takeover',
  port_open: 'Open port',
  service_detected: 'Exposed service',
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'none']

/** The attribution review queue page. */
export const EASM_REVIEW_HREF = '/attack-surface/review'

/** The API's severity string as a known severity (unknown → info). */
export function toSeverity(s: string | undefined): Severity {
  return SEVERITIES.includes(s as Severity) ? (s as Severity) : 'info'
}

export function exposureTypeLabel(t: string): string {
  return (
    EXPOSURE_TYPE_LABEL[t] ??
    EVENT_TYPE_CONFIG[t as ExposureEventType]?.label ??
    t.replace(/_/g, ' ')
  )
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
  const { summary, isLoading, error, mutate } = useEASMSummary()

  if (error) {
    return (
      <div className="mt-5">
        <ErrorState title="the external attack surface" error={error} onRetry={() => mutate()} />
      </div>
    )
  }

  const a = summary?.attribution
  const n = summary?.new
  const m = summary?.monitoring
  const risks = summary?.top_risks ?? []

  return (
    <div className="mt-5 grid gap-5 lg:grid-cols-3">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">External surface</CardTitle>
          <CardDescription>Who it belongs to, what is new, how fresh the watch is</CardDescription>
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
                  label="Domains, subdomains, IPs, certificates"
                  value={summary.surface?.total ?? 0}
                />
                <Row label="Confirmed ours" value={a?.confirmed ?? 0} />
                <Row
                  label="Needs review"
                  value={(a?.needs_review ?? 0) + (a?.candidate ?? 0)}
                  hint={
                    (a?.needs_review ?? 0) + (a?.candidate ?? 0) > 0 ? (
                      <>
                        {a?.review_oldest_since && (
                          <>
                            oldest <RelativeTime date={a.review_oldest_since} className="text-xs" />
                            {' · '}
                          </>
                        )}
                        <Link
                          href={EASM_REVIEW_HREF}
                          className="font-medium text-foreground underline underline-offset-2"
                        >
                          Review
                        </Link>
                      </>
                    ) : undefined
                  }
                />
                {(a?.dependency ?? 0) + (a?.monitor_only ?? 0) > 0 && (
                  <Row
                    label="Dependency or monitor only"
                    value={(a?.dependency ?? 0) + (a?.monitor_only ?? 0)}
                  />
                )}
              </div>
              <div className="py-2">
                <Row label="New in the last 7 days" value={n?.last_7_days ?? 0} />
                <Row label="New in the last 30 days" value={n?.last_30_days ?? 0} />
                <Row
                  label="New since the CTEM cycle started"
                  value={n?.since_cycle ?? '—'}
                  hint={n?.since_cycle === undefined ? 'no cycle started' : undefined}
                />
              </div>
              <div className="pt-2">
                <Row label="Domains watched in CT logs" value={m?.ct_domains_watched ?? 0} />
                {(m?.ct_failing ?? 0) > 0 && (
                  <Row label="CT lookups failing" value={m?.ct_failing} />
                )}
                <Row
                  label="Oldest CT check"
                  value={m?.ct_oldest_success ? <RelativeTime date={m.ct_oldest_success} /> : '—'}
                  hint={
                    !m?.ct_oldest_success && (m?.ct_domains_watched ?? 0) > 0
                      ? 'not checked yet'
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
          <CardTitle className="text-base">Top external risks</CardTitle>
          <CardDescription>
            Open external exposures, most severe first
            {summary?.exposures?.open ? ` · ${summary.exposures.open} open in total` : ''}
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
              title="No open external risks"
              description="Nothing of medium severity or above is open on the external surface."
              card={false}
            />
          ) : (
            <ul className="divide-y" aria-label="Top external risks">
              {risks.map((r) => (
                <li key={r.id} className="flex items-center gap-3 py-2 text-sm">
                  <SeverityBadge severity={toSeverity(r.severity)} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{r.title}</div>
                    <div className="truncate text-xs text-muted-foreground">
                      {exposureTypeLabel(r.type ?? '')}
                      {r.asset_name ? ` · ${r.asset_name}` : ''}
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
              All exposures
            </Link>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
