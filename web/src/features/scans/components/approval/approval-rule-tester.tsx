'use client'

/**
 * The scan approval rule tester (RFC-073 §4.3): runs a rule set against the
 * organization's saved scans and lists the ones it would hold for approval
 * (and the ones only monitor rules catch). Nothing is saved.
 */

import { useCallback, useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  testScanGovernanceRules,
  type ScanApprovalRule,
  type ScanRuleTestResult,
} from '@/lib/api/scan-approval-hooks'
import { approversText } from './approval-requirement'

export interface ApprovalRuleTesterProps {
  rules: ScanApprovalRule[]
  /** Run on mount (default) or only when asked. */
  auto?: boolean
}

export function ApprovalRuleTester({ rules, auto = true }: ApprovalRuleTesterProps) {
  const { t } = useTranslation()
  const [result, setResult] = useState<ScanRuleTestResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const key = JSON.stringify(rules)

  // Keyed by the rules' content, so a new array with the same rules does
  // not run the test again.
  const run = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      setResult(await testScanGovernanceRules(JSON.parse(key) as ScanApprovalRule[]))
    } catch (e) {
      setResult(null)
      setError(getErrorMessage(e, t('scans.ruleTester.failed', 'The rules could not be tested')))
    } finally {
      setBusy(false)
    }
  }, [key, t])

  useEffect(() => {
    if (auto) void run()
  }, [run, auto])

  return (
    <section className="space-y-3 rounded-md border p-3" aria-live="polite">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium">{t('scans.ruleTester.title', 'On existing scans')}</h3>
        <Button size="sm" variant="outline" onClick={() => void run()} disabled={busy}>
          {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
          {result ? t('scans.ruleTester.rerun', 'Test again') : t('scans.ruleTester.run', 'Test')}
        </Button>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {result && (
        <>
          <p className="text-sm text-muted-foreground">
            {t(
              'scans.ruleTester.summary',
              '{caught} of {tested} scans would wait for approval; {monitored} only caught by monitor rules.',
              { caught: result.caught, tested: result.tested, monitored: result.monitored }
            )}
            {result.truncated &&
              ` ${t(
                'scans.ruleTester.truncated',
                'Only the newest {tested} of {total} scans were tested.',
                {
                  tested: result.tested,
                  total: result.total,
                }
              )}`}
          </p>
          {result.scans.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('scans.ruleTester.scan', 'Scan')}</TableHead>
                  <TableHead>{t('scans.ruleTester.intensity', 'Intensity')}</TableHead>
                  <TableHead>{t('scans.ruleTester.rules', 'Caught by')}</TableHead>
                  <TableHead>{t('scans.ruleTester.needs', 'Needs')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.scans.map((s) => (
                  <TableRow key={s.scan_id}>
                    <TableCell>
                      <Link
                        href={`/scans/${encodeURIComponent(s.scan_id)}`}
                        className="hover:underline"
                      >
                        {s.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      {t(`scans.ruleEditor.intensity.${s.intensity}`, s.intensity)}
                    </TableCell>
                    <TableCell className="space-x-1">
                      {[...(s.evaluation.matched ?? []), ...(s.evaluation.monitored ?? [])].map(
                        (r) => (
                          <Badge key={r.id} variant={r.monitor ? 'outline' : 'secondary'}>
                            {r.name}
                          </Badge>
                        )
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {s.evaluation.required
                        ? approversText(t, s.evaluation)
                        : t('scans.ruleTester.monitorOnly', 'Recorded only')}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </>
      )}
    </section>
  )
}
