'use client'

/**
 * Refused CI pipelines (api RFC-051): the latest token exchanges no trust
 * configuration admitted, with the rules that refused them and how to fix
 * each, so whoever sets up a pipeline sees why it does not report.
 */

import { useMemo, useState } from 'react'
import { ArrowRight, ShieldX } from 'lucide-react'
import Link from '@/components/link'
import { ErrorState, RelativeTime } from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useTrustRefusals } from '../api/use-ci'
import { PROVIDER_LABEL, isKnownRefusal } from '../lib/ci'
import { refusalFixes, type RefusalFix } from '../lib/connect'
import { groupRefusals, REFUSAL_GROUPS_PAGE } from '../lib/refusal-groups'
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

/** The reasons of one refusal in plain words, one line each (they wrap on a phone). */
export function RefusalReasons({ reasons }: { reasons?: string[] }) {
  const { t } = useTranslation()
  return (
    <ul className="space-y-0.5" data-testid="ci-refusal-reasons">
      {(reasons ?? []).map((code) => (
        <li key={code} className="flex items-start gap-1.5 font-medium">
          <ShieldX className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
          <span className="min-w-0 break-words">{refusalText(code, t).reason}</span>
        </li>
      ))}
    </ul>
  )
}

/** The button text of a one-click fix. */
export function fixLabel(fix: RefusalFix, t: TFn): string {
  switch (fix.kind) {
    case 'allowBranch':
      return t('scans.ci.fix.allowBranch', 'Allow branch {value}', { value: fix.value })
    case 'allowRepository':
      return t('scans.ci.fix.allowRepository', 'Allow project {value}', { value: fix.value })
    case 'addDefinition':
      return t('scans.ci.fix.addDefinition', 'Add this pipeline file')
    case 'openDefinitions':
      return t('scans.ci.fix.openDefinitions', 'Open pipeline files')
    case 'protectedBranch':
      return t('scans.ci.fix.protectedBranch', 'Change the branch rule')
  }
}

/**
 * One refusal: where it came from, when, and why with the fix. With
 * `onFix`, each fix that changes a configuration is a button; the change is
 * shown in the configuration's editor and saved only from there.
 */
export function RefusalDetail({
  refusal,
  onFix,
  count = 1,
}: {
  refusal: CITokenRefusal
  onFix?: (fix: RefusalFix) => void
  /** How many identical jobs this refusal stands for (a group). */
  count?: number
}) {
  const { t } = useTranslation()
  const fixButtons = onFix ? refusalFixes(refusal) : []
  const definition = fixButtons.find((f) => f.kind === 'addDefinition')
  const fixes = (refusal.reasons ?? [])
    .map((code) => refusalText(code, t).fix)
    .filter((f): f is string => !!f)
  return (
    <div className="space-y-1 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="break-words font-medium">
          {refusal.repository || t('scans.ci.refusals.unknownRepository', 'Unknown repository')}
        </span>
        {refusal.provider && (
          <Badge variant="secondary">{PROVIDER_LABEL[refusal.provider] ?? refusal.provider}</Badge>
        )}
        {count > 1 && (
          <Badge variant="outline" data-testid="ci-refusal-count">
            {t('scans.ci.refusals.times', '{count} jobs', { count })}
          </Badge>
        )}
        {refusal.at && (
          <span className="text-muted-foreground">
            {count > 1 && `${t('scans.ci.refusals.lastSeen', 'last')} `}
            <RelativeTime date={refusal.at} />
          </span>
        )}
      </div>
      {(refusal.ref || refusal.event) && (
        <div className="break-words text-muted-foreground">
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
      {definition?.kind === 'addDefinition' && (
        <p
          className="break-words text-xs text-muted-foreground"
          data-testid="ci-refusal-definition"
        >
          {t('scans.ci.fix.tokenSays', 'The job names: {value}', { value: definition.value })}
        </p>
      )}
      {fixButtons.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-1">
          {fixButtons.map((f) => (
            <Button
              key={f.kind}
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onFix?.(f)}
            >
              {fixLabel(f, t)}
            </Button>
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * Refused jobs, identical ones (same repository, ref, rule and fix) folded
 * into one row with their count and the last time seen. The first `page`
 * groups show; "Show more" adds a page at a time, so a pipeline refused on
 * every push never becomes an endless list.
 */
export function RefusalGroupList({
  refusals,
  onFix,
  canFix,
  page = REFUSAL_GROUPS_PAGE,
  testId,
}: {
  refusals: CITokenRefusal[]
  onFix?: (refusal: CITokenRefusal, fix: RefusalFix) => void
  /** Whether a configuration exists for the fix to edit (all, when left out). */
  canFix?: (refusal: CITokenRefusal) => boolean
  page?: number
  testId?: string
}) {
  const { t } = useTranslation()
  const groups = useMemo(() => groupRefusals(refusals), [refusals])
  const [limit, setLimit] = useState(page)
  const shown = groups.slice(0, limit)
  const rest = groups.length - shown.length
  return (
    <>
      <ul className="divide-y rounded-lg border" data-testid={testId}>
        {shown.map((g) => (
          <li key={g.key} className="p-3" data-testid="ci-refusal">
            <RefusalDetail
              refusal={g.refusal}
              count={g.count}
              onFix={
                onFix && (!canFix || canFix(g.refusal)) ? (f) => onFix(g.refusal, f) : undefined
              }
            />
          </li>
        ))}
      </ul>
      {(rest > 0 || limit > page) && (
        <div className="flex justify-end">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setLimit((l) => (rest > 0 ? l + page : page))}
          >
            {rest > 0
              ? t('scans.ci.refusals.showMore', 'Show {count} more', {
                  count: Math.min(rest, page),
                })
              : t('scans.ci.refusals.showFewer', 'Show fewer')}
          </Button>
        </div>
      )}
    </>
  )
}

/** How many refusal groups the Trusted pipelines section shows before "Show more". */
export const REFUSALS_SHOWN = 3

/** The heading id of the refused pipelines block, the target of the Pipelines tab's notice. */
export const REFUSALS_ID = 'ci-setup-refused'

/** The window the Pipelines tab's notice counts refusals over. */
export const REFUSAL_NOTICE_DAYS = 7

/** Refusals at or after `now - days`. */
export function recentRefusals(
  list: CITokenRefusal[],
  now: number,
  days = REFUSAL_NOTICE_DAYS
): CITokenRefusal[] {
  const since = now - days * 86_400_000
  return list.filter((r) => !!r.at && Date.parse(r.at) >= since)
}

/**
 * One line above the pipelines for a CI writer: pipelines were refused
 * lately, and where to see why. A refused pipeline never appears in the
 * list, so without this line a wrong trust rule looks like silence.
 */
export function CIRefusalNotice({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const { data } = useTrustRefusals({ enabled: canWrite })
  // The clock is read once per mount; a render must not change the answer.
  const [now] = useState(() => Date.now())
  if (!canWrite) return null
  const n = recentRefusals(data?.data ?? [], now).length
  if (n === 0) return null
  return (
    <p
      className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm"
      data-testid="ci-refusal-notice"
    >
      <ShieldX className="size-4 shrink-0 text-warning" aria-hidden />
      <span>
        {t(
          n === 1 ? 'scans.ci.refusals.notice.one' : 'scans.ci.refusals.notice.other',
          n === 1
            ? '1 pipeline was refused in the last {days} days.'
            : '{count} pipelines were refused in the last {days} days.',
          { count: n, days: REFUSAL_NOTICE_DAYS }
        )}
      </span>
      <Link
        href="/ci-cd?tab=connections&refused=1"
        className="inline-flex items-center gap-1 rounded-sm font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {t('scans.ci.refusals.noticeLink', 'See why')}
        <ArrowRight className="size-3.5" aria-hidden />
      </Link>
    </p>
  )
}

/**
 * Recent refused pipelines under Trusted pipelines (CI write only): the
 * latest few, newest first, each with why and how to fix it.
 */
export function CITrustRefusals({
  canWrite,
  onFix,
  canFix,
  bare = false,
}: {
  canWrite: boolean
  /** Without its heading (inside a sheet that names it). */
  bare?: boolean
  /** Open the configuration a refusal's fix edits. */
  onFix?: (refusal: CITokenRefusal, fix: RefusalFix) => void
  /** Whether a configuration exists for the fix to edit. */
  canFix?: (refusal: CITokenRefusal) => boolean
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useTrustRefusals({ enabled: canWrite })
  if (!canWrite) return null
  const list = data?.data ?? []
  return (
    <section aria-labelledby={REFUSALS_ID} className="space-y-2" data-testid="ci-refusals">
      <div className={bare ? 'sr-only' : undefined}>
        <h3 id={REFUSALS_ID} className="flex items-center gap-2 text-sm font-medium">
          <ShieldX className="size-4 text-muted-foreground" aria-hidden />
          {t('scans.ci.refusals.title', 'Recent refused pipelines')}
        </h3>
        <p className="text-sm text-muted-foreground">
          {t(
            'scans.ci.refusals.description',
            'Pipelines whose identity no trust configuration admitted, with the rule that refused each one.'
          )}
        </p>
      </div>
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
        <RefusalGroupList
          refusals={list}
          onFix={onFix}
          canFix={canFix ?? (() => false)}
          page={bare ? REFUSAL_GROUPS_PAGE : REFUSALS_SHOWN}
        />
      )}
    </section>
  )
}
