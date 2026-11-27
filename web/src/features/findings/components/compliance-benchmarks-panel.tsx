'use client'

/**
 * The compliance view of the findings list (shown under the Compliance
 * practice): one row per benchmark with its pass rate over the caller's
 * assets, failing benchmarks first. A row opens the benchmark's controls,
 * failed first, each opening to the assets it was checked on.
 *
 * The pass rate is passed / (passed + failed); not applicable, could not run
 * and needs review are shown beside it and never counted.
 */

import * as React from 'react'
import { ChevronDown, ClipboardCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { ErrorState } from '@/features/shared/components/error-state'
import { formatRelative } from '@/lib/format-date'
import { useComplianceBenchmarks, type ComplianceBenchmark } from '../api/compliance-checks-api'
import { ComplianceBenchmarkSheet } from './compliance-benchmark-sheet'
import { PassRate } from './compliance-pass-rate'

function BenchmarkRow({
  b,
  onOpen,
}: {
  b: ComplianceBenchmark
  onOpen: (b: ComplianceBenchmark) => void
}) {
  const { t, locale } = useTranslation()
  const name = [b.name, b.version && `v${b.version}`].filter(Boolean).join(' ')
  return (
    <TableRow
      className="cursor-pointer"
      data-testid={`compliance-benchmark-${b.key}`}
      onClick={() => onOpen(b)}
    >
      <TableCell className="max-w-80">
        <button
          type="button"
          className="text-start font-medium [overflow-wrap:anywhere] hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          onClick={(e) => {
            e.stopPropagation()
            onOpen(b)
          }}
        >
          {name}
        </button>
      </TableCell>
      <TableCell>
        <PassRate
          rate={b.pass_rate}
          label={t('findings.complianceView.passRateOf', 'Pass rate of {name}', { name })}
        />
      </TableCell>
      <TableCell className="text-sm tabular-nums">
        {t('findings.complianceView.failingAssets', '{failing} of {total}', {
          failing: b.failing_assets,
          total: b.assets,
        })}
      </TableCell>
      <TableCell className="text-sm tabular-nums">
        {t('findings.complianceView.checks', '{fail} failed, {pass} passed', {
          fail: b.counts.fail,
          pass: b.counts.pass,
        })}
        {b.counts.excepted > 0 && (
          <span className="ms-1 text-muted-foreground">
            {t('findings.complianceView.excepted', '({count} excepted)', {
              count: b.counts.excepted,
            })}
          </span>
        )}
      </TableCell>
      <TableCell className="text-sm whitespace-nowrap text-muted-foreground">
        {formatRelative(b.last_checked_at, '', locale)}
      </TableCell>
    </TableRow>
  )
}

/** Per-browser memory of a folded block (a convenience: storage may be absent). */
const FOLD_KEY = 'findings.complianceBenchmarks.folded'
function readFolded(): boolean {
  try {
    return window.localStorage.getItem(FOLD_KEY) === '1'
  } catch {
    return false
  }
}
function writeFolded(folded: boolean) {
  try {
    if (folded) window.localStorage.setItem(FOLD_KEY, '1')
    else window.localStorage.removeItem(FOLD_KEY)
  } catch {
    // Storage blocked: the block still folds for this visit.
  }
}

/**
 * The benchmarks block. It is content of the list, not its chrome: the page
 * draws it under the chips row and above the rows (`DataTable` `beforeRows`),
 * so the title row and the toolbar never move when it loads. It folds to its
 * heading.
 */
export function ComplianceBenchmarksPanel() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useComplianceBenchmarks()
  const [open, setOpen] = React.useState<ComplianceBenchmark | null>(null)
  const [folded, setFolded] = React.useState(false)
  React.useEffect(() => setFolded(readFolded()), [])
  const bodyId = React.useId()
  const rows = data?.data ?? []

  let body: React.ReactNode
  if (error) {
    body = (
      <ErrorState
        title={t('findings.complianceView.title', 'Benchmarks')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  } else if (isLoading && !data) {
    body = <Skeleton className="h-24 w-full" />
  } else if (rows.length === 0) {
    // Nothing to show: no block at all. The list's empty body says what to do
    // (the practice's first run), in the table, where empty content belongs.
    return null
  } else {
    body = (
      <div className="overflow-x-auto">
        <Table data-testid="compliance-benchmarks">
          <TableHeader>
            <TableRow>
              <TableHead>{t('findings.complianceView.benchmark', 'Benchmark')}</TableHead>
              <TableHead>{t('findings.complianceView.passRate', 'Pass rate')}</TableHead>
              <TableHead>{t('findings.complianceView.assetsFailing', 'Assets failing')}</TableHead>
              <TableHead>{t('findings.complianceView.controlChecks', 'Control checks')}</TableHead>
              <TableHead>{t('findings.complianceView.lastChecked', 'Last checked')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((b) => (
              <BenchmarkRow key={b.key} b={b} onOpen={setOpen} />
            ))}
          </TableBody>
        </Table>
      </div>
    )
  }

  return (
    <>
      <DetailSection
        title={t('findings.complianceView.title', 'Benchmarks')}
        icon={ClipboardCheck}
        actions={
          <>
            {rows.length > 0 && !folded && (
              <span className="text-xs text-muted-foreground">
                {t(
                  'findings.complianceView.rateHint',
                  'Pass rate: passed checks out of passed and failed. Not applicable and checks that could not run are not counted.'
                )}
              </span>
            )}
            <Button
              variant="ghost"
              size="icon-sm"
              data-slot="compliance-benchmarks-fold"
              aria-expanded={!folded}
              aria-controls={bodyId}
              aria-label={
                folded
                  ? t('findings.complianceView.unfold', 'Show benchmarks')
                  : t('findings.complianceView.fold', 'Hide benchmarks')
              }
              onClick={() => {
                writeFolded(!folded)
                setFolded(!folded)
              }}
            >
              <ChevronDown
                className={folded ? 'h-4 w-4 -rotate-90 rtl:rotate-90' : 'h-4 w-4'}
                aria-hidden
              />
            </Button>
          </>
        }
      >
        <div id={bodyId} data-testid="compliance-benchmarks-panel" hidden={folded}>
          {body}
        </div>
      </DetailSection>
      <ComplianceBenchmarkSheet benchmark={open} onClose={() => setOpen(null)} />
    </>
  )
}
