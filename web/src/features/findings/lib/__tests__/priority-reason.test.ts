import { describe, expect, it } from 'vitest'
import { translate, type TranslateVars } from '@/lib/i18n'
import { vi as viDict } from '@/lib/i18n/dictionaries/vi'
import { priorityReasonText } from '../priority-reason'

const tVi = (key: string, fallback?: string, vars?: TranslateVars) =>
  translate(viDict, key, fallback, vars, 'vi')

// The reasons ClassifyPriority writes (server/pkg/domain/vulnerability/priority.go).
const SERVER_REASONS = [
  'Informational finding — no remediation required',
  'In CISA KEV (known exploited) and reachable (from 3 entry points)',
  'In CISA KEV (known exploited) on crown jewel asset',
  'EPSS 62.0% (top 1.5%), reachable',
  'EPSS 62.0%, reachable, critical asset',
  'high severity, reachable',
  'In CISA KEV (known exploited); reachability unknown',
  'EPSS 12.0% (top 9%); reachability unknown',
  'EPSS 12.0% on a high asset; reachability unknown',
  'critical severity but not reachable from attacker perspective',
  'high severity; reachability unknown (no exposure or attack-path data for this asset)',
  'high severity; reachable on internal networks only, not from the internet',
  'Medium severity, reachable',
  'Low likelihood/impact',
  'medium severity; reachability unknown',
  'Reachable on internal networks only, not from the internet',
  'Not reachable from attacker perspective',
  'low severity — track and fix opportunistically',
]

describe('priorityReasonText', () => {
  it('words every classifier reason from the catalog in Vietnamese', () => {
    for (const reason of SERVER_REASONS) {
      const vi = priorityReasonText(reason, tVi)
      expect(vi, reason).not.toBe(priorityReasonText(reason))
      expect(vi, reason).not.toMatch(/findings\.priorityReason|severity|reachab/)
    }
    expect(priorityReasonText('Medium severity, reachable', tVi)).toBe(
      'Mức Trung bình, tiếp cận được.'
    )
  })

  it('keeps the EPSS figures', () => {
    expect(priorityReasonText('EPSS 62.0% (top 1.5%), reachable')).toBe(
      'EPSS 62.0% (top 1.5%), reachable.'
    )
  })

  it('words each note and keeps one it does not know as written', () => {
    expect(
      priorityReasonText(
        'high severity, reachable · capped at P2 until ownership is confirmed (was P1; asset attribution: needs_review) · custom rule hit',
        tVi
      )
    ).toBe(
      'Mức Cao, tiếp cận được. Giữ ở P2 cho đến khi xác nhận tài sản là của bạn (trước là P1). Custom rule hit.'
    )
  })

  it('is empty without a reason', () => {
    expect(priorityReasonText(undefined)).toBe('')
    expect(priorityReasonText('  ')).toBe('')
  })
})
