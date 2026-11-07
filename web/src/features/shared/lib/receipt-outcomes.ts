/**
 * Where the findings a receipt received went (api docs/architecture/ingest-receipts.md,
 * "Outcomes"): one shared vocabulary for the receipt view and the dashboard
 * funnel, so both explain every received finding the same way.
 */

import type { useTranslation } from '@/context/i18n-provider'

type T = ReturnType<typeof useTranslation>['t']

/** Outcome codes the API sends (ingestreceipt.AllOutcomes), in display order. */
export const RECEIPT_OUTCOME_CODES = [
  'merged',
  'exposure',
  'source_mitigated',
  'unresolved_ref',
  'out_of_contract',
  'reserved_tool',
  'compliance_passed',
  'quarantined',
  'split',
] as const

export type ReceiptOutcomeCode = (typeof RECEIPT_OUTCOME_CODES)[number]

export function receiptOutcomeLabel(t: T, code: ReceiptOutcomeCode): string {
  switch (code) {
    case 'merged':
      return t('findings.receipts.outcome.merged', 'Repeated in the same scan')
    case 'exposure':
      return t('findings.receipts.outcome.exposure', 'Filed as exposures')
    case 'source_mitigated':
      return t('findings.receipts.outcome.source_mitigated', 'Mitigated at the source')
    case 'unresolved_ref':
      return t('findings.receipts.outcome.unresolved_ref', 'Named no asset, refused')
    case 'out_of_contract':
      return t(
        'findings.receipts.outcome.out_of_contract',
        "Held for review, outside the tool's contract"
      )
    case 'reserved_tool':
      return t('findings.receipts.outcome.reserved_tool', 'Refused, reserved tool name')
    case 'compliance_passed':
      return t('findings.receipts.outcome.compliance_passed', 'Compliance checks that passed')
    case 'quarantined':
      return t('findings.receipts.outcome.quarantined', 'Held in the results quarantine')
    case 'split':
      return t('findings.receipts.outcome.split', 'Added by splitting findings with several CVEs')
  }
}

/** The parts of what a set of receipts received (the dashboard intake noise). */
export interface ReceivedParts {
  received: number
  new: number
  suppressed: number
  not_stored: number
  seen_again?: number
  repeated?: number
  outcomes?: Record<string, number>
  unaccounted?: number
}

/**
 * The full reconciliation of received findings as label and value rows:
 * new or reopened first, then every other place a finding went (rows with
 * nothing are left out), then what no receipt explains (receipts written
 * before outcomes were counted).
 */
export function receivedBreakdown(t: T, p: ReceivedParts): Array<[string, number]> {
  const rows: Array<[string, number]> = [
    [t('dashboardKit.flow.tip.received', 'Findings received'), p.received],
    [t('dashboardKit.flow.tip.newOrReopened', 'New or reopened'), p.new],
  ]
  const optional: Array<[string, number]> = [
    [t('dashboardKit.flow.tip.seenAgainUnchanged', 'Seen again, unchanged'), p.seen_again ?? 0],
    [receiptOutcomeLabel(t, 'merged'), p.repeated ?? 0],
    [t('dashboardKit.flow.tip.suppressed', 'Closed on arrival by a rule'), p.suppressed],
    [t('dashboardKit.flow.tip.notStored', 'Not stored'), p.not_stored],
    ...RECEIPT_OUTCOME_CODES.filter((c) => c !== 'merged').map((c): [string, number] => [
      receiptOutcomeLabel(t, c),
      p.outcomes?.[c] ?? 0,
    ]),
    [t('dashboardKit.flow.tip.unaccounted', 'Not explained by older receipts'), p.unaccounted ?? 0],
  ]
  return rows.concat(optional.filter(([, v]) => v !== 0))
}

/** A receipt's counts of the findings it received (ingestreceipt.Counts). */
export interface ReceiptFindingCounts {
  created: number
  stillDetected: number
  reopened: number
  suppressed: number
  failed: number
  skipped: number
}

/**
 * How many received findings no count and no outcome explains
 * (ingestreceipt.Unaccounted): 0 on a reconciled receipt. Split adds to the
 * received side; closed and untouched are not part of the sum. Codes this
 * build does not know are left out.
 */
export function unaccountedFindings(
  received: number,
  c: ReceiptFindingCounts,
  outcomes?: Record<string, number>
): number {
  let n = received - c.created - c.stillDetected - c.reopened - c.suppressed - c.failed - c.skipped
  for (const code of RECEIPT_OUTCOME_CODES) {
    const v = outcomes?.[code] ?? 0
    n += code === 'split' ? v : -v
  }
  return n
}
