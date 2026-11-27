import { describe, it, expect } from 'vitest'
import {
  acceptedRiskSummary,
  approversSummary,
  deadlineSummary,
  falsePositiveSummary,
  groupTiers,
  kindTiers,
  suppressionRuleSummary,
} from '../approval-summary'
import { cellsFromPolicy } from '../approval-policy'
import { translate } from '@/lib/i18n'

// The default text of every key, with its values (and plural blocks) filled in.
const t = ((k: string, d: string, v?: Record<string, string | number>) =>
  translate({}, k, d, v, 'en')) as never

const defaults: Record<string, string> = {
  'false_positive.standard': 'peer',
  'false_positive.high': 'peer',
  'false_positive.critical': 'peer',
  'accepted.standard': 'peer',
  'accepted.high': 'security',
  'accepted.critical': 'dual',
  'rule_false_positive.standard': 'peer',
  'rule_false_positive.high': 'security',
  'rule_false_positive.critical': 'security',
  'rule_accepted.standard': 'peer',
  'rule_accepted.high': 'security',
  'rule_accepted.critical': 'dual',
}
const none = cellsFromPolicy(undefined)
const withCells = (tiers: Record<string, string>) =>
  cellsFromPolicy({
    tiers: tiers as never,
    security_pool_strict: false,
    exclude_assignee: false,
    step_up_all_tiers: false,
  })

describe('approval summaries', () => {
  it('groups neighbouring classes with one tier', () => {
    expect(groupTiers(kindTiers('rule_false_positive', none, defaults))).toEqual([
      { classes: ['standard'], tier: 'peer' },
      { classes: ['high', 'critical'], tier: 'security' },
    ])
  })

  it('false positives: the level, then only the classes the organization raised', () => {
    expect(falsePositiveSummary(t, 'all', { cells: none, defaults })).toBe(
      'A second person approves every one.'
    )
    expect(
      falsePositiveSummary(t, 'high_and_above', {
        cells: withCells({ 'false_positive.high': 'dual', 'false_positive.critical': 'dual' }),
        defaults,
      })
    ).toBe('A second person approves serious findings only. High and Critical: Two approvers.')
    expect(falsePositiveSummary(t, 'off', { cells: none, defaults })).toBe('One person decides.')
  })

  it('accepted risks: the tier of every class, and under "off" only cells above the default', () => {
    expect(acceptedRiskSummary(t, 'all', { cells: none, defaults })).toBe(
      'A second person approves every one. Standard: Peer review; High: Security review; Critical: Two approvers.'
    )
    // A cell at the default changes nothing under "off" (one person decides).
    expect(
      acceptedRiskSummary(t, 'off', {
        cells: withCells({ 'accepted.critical': 'dual' }),
        defaults,
      })
    ).toBe('One person decides.')
    expect(
      acceptedRiskSummary(t, 'off', {
        cells: withCells({ 'accepted.standard': 'dual' }),
        defaults,
      })
    ).toBe('One person decides. Standard: Two approvers.')
  })

  it('names every class at once when they share a tier', () => {
    expect(
      acceptedRiskSummary(t, 'all', {
        cells: withCells({
          'accepted.standard': 'dual',
          'accepted.high': 'dual',
          'accepted.critical': 'dual',
        }),
        defaults,
      })
    ).toBe('A second person approves every one. Every finding: Two approvers.')
  })

  it('suppression rules: both kinds', () => {
    expect(suppressionRuleSummary(t, { cells: none, defaults })).toBe(
      'False positive rules: Standard: Peer review; High and Critical: Security review. Accepted risk rules: Standard: Peer review; High: Security review; Critical: Two approvers.'
    )
  })

  it('approvers and deadline', () => {
    expect(
      approversSummary(t, {
        hasGroup: false,
        strict: false,
        excludeAssignee: false,
        stepUpAll: false,
      })
    ).toBe('No security pool.')
    expect(
      approversSummary(t, {
        hasGroup: true,
        groupName: 'AppSec',
        strict: false,
        excludeAssignee: true,
        stepUpAll: true,
      })
    ).toBe('Security pool: AppSec. The assignee may not approve. Every approver signs in again.')
    // A pool whose group cannot be read is still said to be set.
    expect(
      approversSummary(t, {
        hasGroup: true,
        strict: true,
        excludeAssignee: false,
        stepUpAll: false,
      })
    ).toBe('Security pool: A group of your organization, nobody else.')
    expect(deadlineSummary(t, 14, 0.5)).toBe(
      'A request expires after 14 days. An exploit likelihood (EPSS) of 0.5 or more counts as high risk.'
    )
  })
})
