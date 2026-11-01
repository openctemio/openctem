'use client'

/**
 * The blocks of Validation › Overview (research/370): what is waiting for
 * the viewer, coverage of closed P0/P1 findings, the latest re-check
 * outcomes, and one quiet line for switched-off modules. Each count opens
 * the list it counts; a block shows a dash, never a made-up zero, while its
 * figure loads or when it failed.
 */

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useDocsHref } from '@/context/brand-provider'
import { ErrorState, Meter, SettingsSection } from '@/features/shared'
import { DOCS } from '@/lib/docs-links'
import { cn } from '@/lib/utils'
import { useValidationCoverage } from '../api/use-validation-coverage'
import type { ValidationModule } from '../lib/overview-queries'

export interface WaitingItem {
  key: string
  /** undefined while it loads (or when its request failed). */
  count: number | undefined
  title: string
  reason: string
  action: string
  href: string
}

export interface StartLink {
  href: string
  label: string
}

/**
 * The decision list: one row per queue that has something in it, each with
 * the one action that empties it. The first row's action is the primary
 * one; the rest are outline buttons, so the page never has two competing
 * primary actions. With nothing waiting, the block says so and offers the
 * places where validation work starts.
 */
export function WaitingForYou({ items, starts }: { items: WaitingItem[]; starts: StartLink[] }) {
  const { t } = useTranslation()
  const waiting = items.filter((i) => (i.count ?? 0) > 0)
  const loading = items.every((i) => i.count === undefined)

  let body: React.ReactNode
  if (waiting.length > 0) {
    body = (
      <ul className="divide-y" data-testid="validation-waiting">
        {waiting.map((item, idx) => (
          <li
            key={item.key}
            className="grid grid-cols-[2.75rem_minmax(0,1fr)] items-center gap-x-3 gap-y-2 px-4 py-3 sm:grid-cols-[3.5rem_minmax(0,1fr)_auto]"
          >
            <span className="text-xl font-semibold tabular-nums">{item.count}</span>
            <span className="min-w-0">
              <span className="block text-sm font-medium">{item.title}</span>
              <span className="block text-xs text-muted-foreground">{item.reason}</span>
            </span>
            <Button
              asChild
              size="sm"
              variant={idx === 0 ? 'default' : 'outline'}
              className="col-start-2 justify-self-start sm:col-start-auto sm:justify-self-end"
            >
              <Link href={item.href}>{item.action}</Link>
            </Button>
          </li>
        ))}
      </ul>
    )
  } else if (loading) {
    body = <Skeleton className="m-4 h-12" />
  } else {
    body = (
      <div className="space-y-3 px-4 py-4">
        <p className="text-sm text-muted-foreground">
          {starts.length > 0
            ? t(
                'validation.overview.waiting.emptyWithStarts',
                'Nothing is waiting for you. Validation work starts here:'
              )
            : t('validation.overview.waiting.empty', 'Nothing is waiting for you.')}
        </p>
        {starts.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {starts.map((s) => (
              <Button key={s.href} asChild size="sm" variant="outline">
                <Link href={s.href}>{s.label}</Link>
              </Button>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <SettingsSection title={t('validation.overview.waiting.title', 'Waiting for you')}>
      <Card className="py-0">
        <CardContent className="p-0">{body}</CardContent>
      </Card>
    </SettingsSection>
  )
}

const pct = (validated: number, total: number) =>
  total > 0 ? Math.round((validated / total) * 100) : 0

/**
 * Coverage of closed P0 and P1 findings with validation evidence: the
 * figure the CTEM cycle's close gate uses, with its two classes under it
 * and a link to how it is measured.
 */
export function CoverageSummary() {
  const { t } = useTranslation()
  const docsHref = useDocsHref()
  const { data, error, isLoading, mutate } = useValidationCoverage()
  const title = t('validation.overview.coverage.title', 'Validation coverage')
  const total = data?.p0_p1_total ?? 0
  const validated = data?.p0_p1_validated ?? 0
  const rows = (data?.by_priority ?? []).filter((r) => r.priority === 'P0' || r.priority === 'P1')

  let body: React.ReactNode
  if (error) {
    body = <ErrorState title={title} error={error} onRetry={() => void mutate()} />
  } else if (isLoading) {
    body = <Skeleton className="h-28 w-full" />
  } else if (total === 0) {
    body = (
      <>
        <p className="text-4xl leading-none font-semibold text-muted-foreground">–</p>
        <p className="mt-2 text-sm text-muted-foreground">
          {t('validation.overview.coverage.none', 'No P0 or P1 finding has been closed yet.')}
        </p>
      </>
    )
  } else {
    body = (
      <>
        <p className="text-4xl leading-none font-semibold tracking-tight tabular-nums">
          {pct(validated, total)}%
        </p>
        <p className="mt-2 text-sm text-muted-foreground">
          {t(
            'validation.overview.coverage.share',
            '{validated} of {total} closed P0 and P1 findings',
            { validated, total }
          )}
        </p>
        <Meter
          className="my-4 h-1.5"
          value={validated}
          max={total}
          label={t(
            'validation.overview.coverage.share',
            '{validated} of {total} closed P0 and P1 findings',
            { validated, total }
          )}
        />
        <ul className="divide-y border-t text-sm">
          {rows.map((r) => (
            <li key={r.priority} className="flex items-center justify-between py-1.5">
              <span>{r.priority}</span>
              <span className="text-muted-foreground tabular-nums">
                {t('validation.overview.coverage.row', '{validated} of {total}, {pct}%', {
                  validated: r.validated,
                  total: r.total,
                  pct: pct(r.validated, r.total),
                })}
              </span>
            </li>
          ))}
        </ul>
      </>
    )
  }

  return (
    <SettingsSection
      title={title}
      description={t(
        'validation.overview.coverage.description',
        'Closed P0 and P1 findings with validation evidence.'
      )}
    >
      <Card className="py-0">
        <CardContent className="p-4">
          {body}
          <a
            href={docsHref(DOCS.validation.overview)}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-block text-sm underline underline-offset-4"
          >
            {t('validation.overview.coverage.howMeasured', 'How coverage is measured')}
          </a>
        </CardContent>
      </Card>
    </SettingsSection>
  )
}

export interface OutcomeItem {
  key: string
  count: number | undefined
  title: string
  reason: string
  href: string
  /** Colours the count only while it is positive; zero stays neutral. */
  tone?: 'danger' | 'warning'
}

/** The latest re-check verdicts, each a link to its findings list. */
export function OutcomesList({ items }: { items: OutcomeItem[] }) {
  const { t } = useTranslation()
  return (
    <SettingsSection
      title={t('validation.overview.outcomes.title', 'Outcomes')}
      description={t('validation.overview.outcomes.description', 'The latest re-check verdicts.')}
    >
      <Card className="py-0">
        <CardContent className="p-0">
          <ul className="divide-y">
            {items.map((o) => {
              const positive = (o.count ?? 0) > 0
              return (
                <li key={o.key}>
                  <Link
                    href={o.href}
                    className="flex items-start justify-between gap-3 px-4 py-3 hover:bg-muted/50"
                  >
                    <span className="min-w-0">
                      <span className="block text-sm font-medium">{o.title}</span>
                      <span className="block text-xs text-muted-foreground">{o.reason}</span>
                    </span>
                    <span
                      className={cn(
                        'shrink-0 text-lg tabular-nums',
                        positive ? 'font-semibold' : 'font-medium text-muted-foreground',
                        positive && o.tone === 'danger' && 'text-destructive',
                        positive && o.tone === 'warning' && 'text-warning'
                      )}
                    >
                      {o.count === undefined ? '–' : o.count}
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </CardContent>
      </Card>
    </SettingsSection>
  )
}

/**
 * One muted line for owners and admins naming the validation modules the
 * organization switched off, with the way to turn them on. Nothing for
 * anyone else, and nothing when every module is on.
 */
export function ModulesOffHint({ modules }: { modules: ValidationModule[] }) {
  const { t, locale } = useTranslation()
  if (modules.length === 0) return null
  const names: Record<ValidationModule, string> = {
    pentest: t('validation.overview.module.pentest', 'Pentest campaigns'),
    attack_simulation: t('validation.overview.module.attack_simulation', 'Attack simulation'),
    control_testing: t('validation.overview.module.control_testing', 'Control testing'),
    mitre_coverage: t('validation.overview.module.mitre_coverage', 'ATT&CK coverage'),
  }
  const parts = modules.map((m) => names[m])
  let list: string
  try {
    list = new Intl.ListFormat(locale, { type: 'conjunction', style: 'long' }).format(parts)
  } catch {
    list = parts.join(', ')
  }
  return (
    <p className="text-sm text-muted-foreground" data-testid="validation-modules-off">
      {modules.length === 1
        ? t('validation.overview.modulesOff.one', '{list} is switched off.', { list })
        : t('validation.overview.modulesOff.other', '{list} are switched off.', { list })}{' '}
      <Link href="/settings/modules" className="text-foreground underline underline-offset-4">
        {t('validation.overview.modulesOff.link', 'Turn on in Modules')}
      </Link>
    </p>
  )
}
