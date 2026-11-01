'use client'

/**
 * The middle of the attack surface overview (research/353 D4): what to fix
 * first (the most severe open external exposures, each opening its asset)
 * and whether discovery keeps up (decisions waiting, Certificate Transparency
 * freshness, monitoring settings in a drawer). Every number comes from
 * GET /api/v1/easm/summary; nothing is computed from a page of rows.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useState } from 'react'
import Link from '@/components/link'
import { Settings2, ShieldCheck } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { EASMMonitoringCard } from './easm-monitoring-card'
import { EVENT_TYPE_CONFIG, type ExposureEventType } from '@/lib/api/exposure-types'
import { Skeleton } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  KeyValueList,
  RelativeTime,
  SeverityBadge,
  type KeyValueItem,
  type Severity,
} from '@/features/shared'
import { AssetPeekLink } from '@/features/assets/components/asset-peek'
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

/** Open external exposures, most severe first, each with the asset it is on. */
export function EASMTopRisks() {
  const { t } = useTranslation()
  const { summary, isLoading, error, mutate } = useEASMSummary()
  useSettleSignal(isLoading)
  const risks = summary?.top_risks ?? []
  const open = summary?.exposures?.open ?? 0

  return (
    <Card className="lg:col-span-2" data-testid="easm-fix-first">
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 space-y-1.5">
          <CardTitle className="text-base">
            {t('easmReview.overview.fixFirst', 'Fix first')}
          </CardTitle>
          <CardDescription>
            {t('easmReview.overview.risksHint', 'Open external exposures, most severe first')}
          </CardDescription>
        </div>
        <Button size="sm" variant="outline" asChild>
          <Link href="/exposures">
            {open > 0
              ? t('easmReview.overview.allOpen', 'All {n} open', { n: open })
              : t('easmReview.overview.allExposures', 'All exposures')}
          </Link>
        </Button>
      </CardHeader>
      <CardContent>
        {error ? (
          <ErrorState
            title={t('easmReview.overview.errorTitle', 'the external attack surface')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : isLoading || !summary ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
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
          <ul className="divide-y" aria-label={t('easmReview.overview.fixFirst', 'Fix first')}>
            {risks.map((r) => (
              <li key={r.id} className="flex items-center gap-3 py-2.5 text-sm">
                <SeverityBadge severity={toSeverity(r.severity)} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{r.title}</div>
                  <div className="flex min-w-0 gap-x-3 text-xs text-muted-foreground">
                    <span className="shrink-0">{exposureTypeLabel(r.type ?? '', t)}</span>
                    {r.asset_name && (
                      <AssetPeekLink assetId={r.asset_id} className="truncate text-xs">
                        {r.asset_name}
                      </AssetPeekLink>
                    )}
                  </div>
                </div>
                {r.last_seen && (
                  <RelativeTime date={r.last_seen} className="hidden shrink-0 text-xs sm:inline" />
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * Whether discovery keeps up: decisions waiting (with the oldest), names
 * kept passive, and how fresh the Certificate Transparency watch is. The
 * monitoring settings open in a drawer, so the overview reads as a summary.
 */
export function EASMDiscoveryHealth() {
  const { t } = useTranslation()
  const { summary, isLoading, error, mutate } = useEASMSummary()
  const [settingsOpen, setSettingsOpen] = useState(false)
  useSettleSignal(isLoading)
  const a = summary?.attribution
  const m = summary?.monitoring
  const waiting = (a?.needs_review ?? 0) + (a?.candidate ?? 0)
  const items: KeyValueItem[] = summary
    ? [
        {
          key: 'waiting',
          label: t('easmReview.overview.waiting', 'Found, not yet decided'),
          value: (
            <span className="inline-flex flex-wrap items-baseline gap-x-3">
              <span className="tabular-nums">{waiting}</span>
              {waiting > 0 && a?.review_oldest_since && (
                <span className="text-xs text-muted-foreground">
                  {t('easmReview.overview.oldest', 'oldest')}{' '}
                  <RelativeTime date={a.review_oldest_since} className="text-xs" />
                </span>
              )}
            </span>
          ),
        },
        {
          key: 'passive',
          label: t('easmReview.overview.discovered', 'Discovered, passive only until in scope'),
          value: <span className="tabular-nums">{a?.discovered ?? 0}</span>,
        },
        {
          key: 'dependency',
          label: t('easmReview.overview.dependency', 'Dependency or monitor only'),
          value: (
            <span className="tabular-nums">{(a?.dependency ?? 0) + (a?.monitor_only ?? 0)}</span>
          ),
        },
        {
          key: 'ct',
          label: t('easmReview.overview.ctWatched', 'Domains watched in CT logs'),
          value: (
            <span className="inline-flex flex-wrap items-baseline gap-x-3">
              <span className="tabular-nums">{m?.ct_domains_watched ?? 0}</span>
              {(m?.ct_failing ?? 0) > 0 && (
                <span className="text-xs font-medium text-destructive">
                  {t('easmReview.overview.ctFailingN', '{n} failing', { n: m?.ct_failing ?? 0 })}
                </span>
              )}
            </span>
          ),
        },
        {
          key: 'ctOldest',
          label: t('easmReview.overview.ctOldest', 'Oldest CT check'),
          value: m?.ct_oldest_success ? (
            <RelativeTime date={m.ct_oldest_success} />
          ) : (m?.ct_domains_watched ?? 0) > 0 ? (
            t('easmReview.overview.notChecked', 'not checked yet')
          ) : (
            '—'
          ),
        },
      ]
    : []

  return (
    <Card data-testid="easm-discovery-health">
      <CardHeader>
        <CardTitle className="text-base">
          {t('easmReview.overview.discoveryHealth', 'Discovery')}
        </CardTitle>
        <CardDescription>
          {t(
            'easmReview.overview.discoveryHealthHint',
            'What waits for a decision and how fresh the watch is'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error ? (
          <ErrorState
            title={t('easmReview.overview.errorTitle', 'the external attack surface')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : isLoading || !summary ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        ) : (
          <KeyValueList items={items} />
        )}
        <div className="flex flex-wrap gap-2">
          {waiting > 0 && (
            <Button size="sm" asChild>
              <Link href={EASM_REVIEW_HREF}>
                {t('easmReview.overview.decide', 'Decide {n}', { n: waiting })}
              </Link>
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => setSettingsOpen(true)}>
            <Settings2 className="h-4 w-4" aria-hidden />
            {t('easmReview.overview.monitoringSettings', 'Monitoring settings')}
          </Button>
        </div>
      </CardContent>
      <Sheet open={settingsOpen} onOpenChange={setSettingsOpen}>
        <SheetContent className="w-full sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>
              {t('easmReview.overview.monitoringSettings', 'Monitoring settings')}
            </SheetTitle>
            <SheetDescription>
              {t(
                'easmReview.overview.monitoringSettingsHint',
                'How often discovery and DNS checks run, and which lookups leave your network.'
              )}
            </SheetDescription>
          </SheetHeader>
          <SheetBody>{settingsOpen && <EASMMonitoringCard />}</SheetBody>
        </SheetContent>
      </Sheet>
    </Card>
  )
}

/** The overview's middle row: what to fix first and whether discovery keeps up. */
export function EASMOverview() {
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <EASMTopRisks />
      <EASMDiscoveryHealth />
    </div>
  )
}
