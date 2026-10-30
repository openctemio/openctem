'use client'

/**
 * Refused CI pipelines (api RFC-051): the latest token exchanges no trust
 * configuration admitted, with the rules that refused them and how to fix
 * each, so whoever sets up a pipeline sees why it does not report.
 */

import { ShieldX } from 'lucide-react'
import { ErrorState, RelativeTime } from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useTrustRefusals } from '../api/use-ci'
import { PROVIDER_LABEL, isKnownRefusal } from '../lib/ci'
import type { CITokenRefusal } from '../types'

type TFn = ReturnType<typeof useTranslation>['t']

/** The translated reason and fix of a refusal code (the code itself when unknown). */
export function refusalText(code: string, t: TFn): { reason: string; fix: string } {
  if (!isKnownRefusal(code)) return { reason: code, fix: '' }
  return {
    reason: t(`scans.ci.refusal.${code}`, code),
    fix: t(`scans.ci.refusal.${code}Fix`, ''),
  }
}

/** The reasons of one refusal as chips with the fix in the title. */
export function RefusalReasons({ reasons }: { reasons?: string[] }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap gap-1">
      {(reasons ?? []).map((code) => {
        const { reason, fix } = refusalText(code, t)
        return (
          <Badge key={code} variant="outline" title={fix || undefined}>
            {reason}
          </Badge>
        )
      })}
    </div>
  )
}

/** One refusal: where it came from, when, and why with the fix. */
export function RefusalDetail({ refusal }: { refusal: CITokenRefusal }) {
  const { t } = useTranslation()
  const fixes = (refusal.reasons ?? [])
    .map((code) => refusalText(code, t).fix)
    .filter((f): f is string => !!f)
  return (
    <div className="space-y-1 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="break-all font-medium">
          {refusal.repository || t('scans.ci.refusals.unknownRepository', 'Unknown repository')}
        </span>
        {refusal.provider && (
          <Badge variant="secondary">{PROVIDER_LABEL[refusal.provider] ?? refusal.provider}</Badge>
        )}
        {refusal.at && <RelativeTime date={refusal.at} className="text-muted-foreground" />}
      </div>
      {(refusal.ref || refusal.event) && (
        <div className="break-all text-muted-foreground">
          {[refusal.event, refusal.ref].filter(Boolean).join(', ')}
        </div>
      )}
      <RefusalReasons reasons={refusal.reasons} />
      {fixes.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
          {fixes.map((f) => (
            <li key={f}>{f}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** The Trust tab card: recent refused pipelines (CI write only). */
export function CITrustRefusals({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useTrustRefusals({ enabled: canWrite })
  if (!canWrite) return null
  const list = data?.data ?? []
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldX className="size-4" aria-hidden />
          {t('scans.ci.refusals.title', 'Recent refused pipelines')}
        </CardTitle>
        <CardDescription>
          {t(
            'scans.ci.refusals.description',
            'Pipelines whose identity no trust configuration admitted, with the rule that refused each one.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {error ? (
          <ErrorState
            title={t('scans.ci.refusals.title', 'Recent refused pipelines')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : list.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t('scans.ci.refusals.none', 'No pipeline has been refused recently.')}
          </p>
        ) : (
          list.map((r, i) => (
            <div key={`${r.at}-${i}`} className="border-b pb-3 last:border-b-0 last:pb-0">
              <RefusalDetail refusal={r} />
            </div>
          ))
        )}
      </CardContent>
    </Card>
  )
}
