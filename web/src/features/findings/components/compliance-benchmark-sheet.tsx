'use client'

/**
 * One benchmark of the compliance view: its controls over the caller's
 * assets, failed first, each with its pass rate; a control opens to the
 * assets it was checked on (result, evidence, the finding). The search and
 * the "failed only" switch are folded into the sheet's toolbar.
 */

import * as React from 'react'
import Link from '@/components/link'
import { ChevronRight } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { ListSearch } from '@/features/shared/components/list-search'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { ToneChip } from '@/components/ui/tone-chip'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { ErrorState } from '@/features/shared/components/error-state'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { useSearchQuery } from '@/hooks/use-search-query'
import { formatRelative } from '@/lib/format-date'
import { safeHref } from '@/lib/safe-href'
import {
  useComplianceControlAssets,
  useComplianceControls,
  type ComplianceBenchmark,
  type ComplianceControl,
  type ComplianceResult,
} from '../api/compliance-checks-api'
import { RESULT_TEXT, RESULT_TONE } from '../lib/compliance-posture'
import { PassRate } from './compliance-pass-rate'

export function ComplianceResultChip({ result }: { result: ComplianceResult }) {
  const { t } = useTranslation()
  return (
    <ToneChip
      tone={RESULT_TONE[result]}
      value={result}
      label={t(`findings.filter.value.compliance_result.${result}`, RESULT_TEXT[result])}
    />
  )
}

function ControlAssets({ benchmarkKey, control }: { benchmarkKey: string; control: string }) {
  const { t, locale } = useTranslation()
  const { data, error, isLoading } = useComplianceControlAssets(benchmarkKey, control)
  if (error) {
    return <ErrorState title={t('findings.complianceView.assets', 'Assets')} error={error} />
  }
  if (isLoading && !data) return <Skeleton className="h-12 w-full" />
  const rows = data?.data ?? []
  return (
    <ul className="divide-y rounded-md border" data-testid={`compliance-control-assets-${control}`}>
      {rows.map((a) => {
        const findingHref = a.finding_id
          ? safeHref(`/findings/${encodeURIComponent(a.finding_id)}`)
          : undefined
        return (
          <li key={a.asset_id} className="space-y-2 px-3 py-2">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <ComplianceResultChip result={a.result} />
              <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{a.asset_name}</span>
              <span className="text-xs text-muted-foreground">
                {t('findings.complianceView.checkedAt', 'checked {when}', {
                  when: formatRelative(a.last_checked_at, '', locale),
                })}
              </span>
              {findingHref && (
                <Link
                  href={findingHref}
                  className="ms-auto text-sm text-primary hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                >
                  {t('findings.complianceView.openFinding', 'Open finding')}
                </Link>
              )}
            </div>
            {(a.evidence.actual || a.evidence.expected || a.evidence.message) && (
              <details className="text-sm">
                <summary className="cursor-pointer text-muted-foreground select-none">
                  {t('findings.complianceView.evidence', 'What the check saw')}
                </summary>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  {a.evidence.expected && (
                    <UntrustedTextBlock
                      text={a.evidence.expected}
                      label={t('findings.compliance.expected', 'Expected (policy) value')}
                      caption={t('findings.compliance.expected', 'Expected (policy) value')}
                      collapseLines={6}
                    />
                  )}
                  {a.evidence.actual && (
                    <UntrustedTextBlock
                      text={a.evidence.actual}
                      label={t('findings.compliance.actual', 'Actual value')}
                      caption={t('findings.compliance.actual', 'Actual value')}
                      collapseLines={6}
                    />
                  )}
                  {a.evidence.message && (
                    <UntrustedTextBlock
                      text={a.evidence.message}
                      label={t('findings.complianceView.message', 'Scanner message')}
                      caption={t('findings.complianceView.message', 'Scanner message')}
                      collapseLines={6}
                    />
                  )}
                </div>
              </details>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function ControlRow({ benchmarkKey, c }: { benchmarkKey: string; c: ComplianceControl }) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(false)
  const label = [c.control_id, c.control_name].filter(Boolean).join(' ')
  return (
    <li data-testid={`compliance-control-${c.control_id}`}>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full min-w-0 items-start gap-2 px-3 py-2 text-start hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <ChevronRight
          className={`mt-1 h-3 w-3 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-90' : ''}`}
          aria-hidden
        />
        <span className="min-w-0 flex-1 space-y-1">
          <span className="block text-sm [overflow-wrap:anywhere]">{label}</span>
          <span className="block text-xs text-muted-foreground tabular-nums">
            {t('findings.complianceView.controlCounts', '{fail} failing, {pass} passing', {
              fail: c.counts.fail,
              pass: c.counts.pass,
            })}
            {c.level
              ? ` ${t('findings.complianceView.level', 'level {level}', { level: c.level })}`
              : ''}
          </span>
        </span>
        <span className="w-40 shrink-0">
          <PassRate
            rate={c.pass_rate}
            label={t('findings.complianceView.passRateOf', 'Pass rate of {name}', {
              name: c.control_id,
            })}
          />
        </span>
      </button>
      {open && (
        <div className="px-3 pb-3 ps-8">
          <ControlAssets benchmarkKey={benchmarkKey} control={c.control_id} />
        </div>
      )}
    </li>
  )
}

export interface ComplianceBenchmarkSheetProps {
  benchmark: ComplianceBenchmark | null
  onClose: () => void
}

export function ComplianceBenchmarkSheet({ benchmark, onClose }: ComplianceBenchmarkSheetProps) {
  const { t } = useTranslation()
  const [input, setInput] = React.useState('')
  const [failedOnly, setFailedOnly] = React.useState(true)
  const [page, setPage] = React.useState(1)
  const { term } = useSearchQuery(input, { minChars: 1 })
  const key = benchmark?.key
  React.useEffect(() => {
    setPage(1)
  }, [key, term, failedOnly])
  const { data, error, isLoading } = useComplianceControls(key, { failedOnly, q: term, page })
  const rows = data?.data ?? []
  const name = benchmark
    ? [benchmark.name, benchmark.version && `v${benchmark.version}`].filter(Boolean).join(' ')
    : ''
  return (
    <Sheet open={!!benchmark} onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="[overflow-wrap:anywhere]">{name}</SheetTitle>
          <SheetDescription>
            {benchmark &&
              t(
                'findings.complianceView.sheetSummary',
                '{failing} of {total} assets fail at least one control.',
                { failing: benchmark.failing_assets, total: benchmark.assets }
              )}
          </SheetDescription>
        </SheetHeader>
        <SheetBody className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <ListSearch
              value={input}
              onChange={setInput}
              placeholder={t('findings.complianceView.search', 'Search controls')}
            />
            <div className="flex items-center gap-2">
              <Switch
                id="compliance-failed-only"
                checked={failedOnly}
                onCheckedChange={setFailedOnly}
              />
              <Label htmlFor="compliance-failed-only">
                {t('findings.complianceView.failedOnly', 'Failing or needing review only')}
              </Label>
            </div>
          </div>
          {error ? (
            <ErrorState title={t('findings.complianceView.controls', 'Controls')} error={error} />
          ) : isLoading && !data ? (
            <Skeleton className="h-32 w-full" />
          ) : rows.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="compliance-controls-empty">
              {failedOnly
                ? t(
                    'findings.complianceView.noFailing',
                    'No control fails on your assets. Turn off the switch to see every control.'
                  )
                : t('findings.complianceView.noControls', 'No control matches.')}
            </p>
          ) : (
            <ul className="divide-y rounded-md border" data-testid="compliance-controls">
              {rows.map((c) => (
                <ControlRow key={c.control_id} benchmarkKey={key ?? ''} c={c} />
              ))}
            </ul>
          )}
          {data && data.total_pages > 1 && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground tabular-nums">
                {t('findings.complianceView.pageOf', 'Page {page} of {pages}', {
                  page: data.page,
                  pages: data.total_pages,
                })}
              </span>
              <span className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  {t('common.previous', 'Previous')}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= data.total_pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  {t('common.next', 'Next')}
                </Button>
              </span>
            </div>
          )}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
