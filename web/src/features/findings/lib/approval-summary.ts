/**
 * The one-line summaries of Settings > Approvals: each approval type is a row
 * that says what is set in plain words ("A second person approves every one.
 * Critical: Two approvers") and opens its editor on demand. The text follows
 * the API's evaluation (server/pkg/domain/approvalpolicy/evaluate.go): a
 * false positive's tier is its level, raised by an organization cell; an
 * accepted risk's tier is its cell or the platform default, and a level that
 * lets one person decide keeps only the cells above that default.
 */

import type { useTranslation } from '@/context/i18n-provider'
import {
  DEFAULT_CELL,
  RISK_CLASSES,
  cellKey,
  riskClassLabel,
  tierLabel,
  tierRank,
  type ApprovalKind,
  type RiskClass,
} from './approval-policy'

type Translate = ReturnType<typeof useTranslation>['t']

/** An approval level of the organization (false positive or accepted risk). */
export type LevelValue = 'all' | 'high_and_above' | 'off'

/** One tier for one or more risk classes in a row. */
export interface TierGroup {
  classes: RiskClass[]
  tier: string
}

/**
 * The tier each class of `kind` has: the organization's cell, else the
 * platform default. `onlySet` keeps only the cells the organization set;
 * `aboveDefault` only those above the platform default.
 */
export function kindTiers(
  kind: ApprovalKind,
  cells: Record<string, string>,
  defaults: Record<string, string>,
  opts: { onlySet?: boolean; aboveDefault?: boolean } = {}
): { cls: RiskClass; tier: string }[] {
  const out: { cls: RiskClass; tier: string }[] = []
  for (const cls of RISK_CLASSES) {
    const key = cellKey(kind, cls)
    const cell = cells[key]
    const set = !!cell && cell !== DEFAULT_CELL
    if ((opts.onlySet || opts.aboveDefault) && !set) continue
    const tier = set ? cell : defaults[key]
    if (!tier) continue
    if (opts.aboveDefault && tierRank(tier) <= tierRank(defaults[key])) continue
    out.push({ cls, tier })
  }
  return out
}

/** Neighbouring classes with the same tier, joined: Standard, High and Critical. */
export function groupTiers(tiers: { cls: RiskClass; tier: string }[]): TierGroup[] {
  const groups: TierGroup[] = []
  for (const { cls, tier } of tiers) {
    const last = groups[groups.length - 1]
    if (last && last.tier === tier) last.classes.push(cls)
    else groups.push({ classes: [cls], tier })
  }
  return groups
}

/** "Critical: Two approvers; High: Security review", or "" when there is none. */
export function tierGroupsText(t: Translate, groups: TierGroup[]): string {
  return groups
    .map((g) =>
      t('findingApprovals.summary.group', '{classes}: {tier}', {
        classes: classesText(t, g.classes),
        tier: tierLabel(t, g.tier),
      })
    )
    .join('; ')
}

function classesText(t: Translate, classes: RiskClass[]): string {
  if (classes.length === RISK_CLASSES.length)
    return t('findingApprovals.summary.everyClass', 'Every finding')
  const names = classes.map((c) => riskClassLabel(t, c))
  if (names.length === 1) return names[0]
  return t('findingApprovals.summary.pair', '{a} and {b}', { a: names[0], b: names[1] })
}

/** Two sentences into one line: "A. B." without a doubled stop. */
function sentences(...parts: string[]): string {
  return parts
    .filter(Boolean)
    .map((p) => (/[.!?]$/.test(p) ? p : `${p}.`))
    .join(' ')
}

/** What a level means, in a few words. */
export function levelSummary(t: Translate, level: LevelValue): string {
  switch (level) {
    case 'high_and_above':
      return t(
        'findingApprovals.summary.level.high_and_above',
        'A second person approves serious findings only'
      )
    case 'off':
      return t('findingApprovals.summary.level.off', 'One person decides')
    default:
      return t('findingApprovals.summary.level.all', 'A second person approves every one')
  }
}

export interface SummaryInput {
  cells: Record<string, string>
  defaults: Record<string, string>
}

/** False positives: the level, then the classes the organization made stricter. */
export function falsePositiveSummary(
  t: Translate,
  level: LevelValue,
  { cells, defaults }: SummaryInput
): string {
  const raised = groupTiers(kindTiers('false_positive', cells, defaults, { onlySet: true }))
  return sentences(levelSummary(t, level), tierGroupsText(t, raised))
}

/** Accepted risks: the level, then the tier each class needs when a second person approves. */
export function acceptedRiskSummary(
  t: Translate,
  level: LevelValue,
  { cells, defaults }: SummaryInput
): string {
  const tiers =
    level === 'off'
      ? kindTiers('accepted', cells, defaults, { aboveDefault: true })
      : kindTiers('accepted', cells, defaults)
  return sentences(levelSummary(t, level), tierGroupsText(t, groupTiers(tiers)))
}

/** Suppression rules: the tiers of both kinds of rule. */
export function suppressionRuleSummary(t: Translate, { cells, defaults }: SummaryInput): string {
  const part = (kind: ApprovalKind, label: string) => {
    const text = tierGroupsText(t, groupTiers(kindTiers(kind, cells, defaults)))
    return text
      ? t('findingApprovals.summary.ruleKind', '{kind}: {tiers}', { kind: label, tiers: text })
      : ''
  }
  return sentences(
    part(
      'rule_false_positive',
      t('findingApprovals.summary.ruleFalsePositive', 'False positive rules')
    ),
    part('rule_accepted', t('findingApprovals.summary.ruleAccepted', 'Accepted risk rules'))
  )
}

/** Approvers: the security pool, then the extra rules that are on. */
export function approversSummary(
  t: Translate,
  p: {
    groupName?: string
    hasGroup: boolean
    strict: boolean
    excludeAssignee: boolean
    stepUpAll: boolean
  }
): string {
  const pool = !p.hasGroup
    ? t('findingApprovals.summary.noPool', 'No security pool')
    : p.strict
      ? t('findingApprovals.summary.poolStrict', 'Security pool: {name}, nobody else', {
          name:
            p.groupName ?? t('findingApprovals.policy.poolUnknown', 'A group of your organization'),
        })
      : t('findingApprovals.summary.pool', 'Security pool: {name}', {
          name:
            p.groupName ?? t('findingApprovals.policy.poolUnknown', 'A group of your organization'),
        })
  return sentences(
    pool,
    p.excludeAssignee
      ? t('findingApprovals.summary.assigneeExcluded', 'The assignee may not approve')
      : '',
    p.stepUpAll ? t('findingApprovals.summary.stepUpAll', 'Every approver signs in again') : ''
  )
}

/** The request deadline and the exploit likelihood that counts as high risk. */
export function deadlineSummary(t: Translate, decideWithinDays: number, epss: number): string {
  return sentences(
    t(
      'findingApprovals.summary.deadline',
      'A request expires after {days, plural, one {# day} other {# days}}',
      {
        days: decideWithinDays,
      }
    ),
    t(
      'findingApprovals.summary.epss',
      'An exploit likelihood (EPSS) of {epss} or more counts as high risk',
      {
        epss,
      }
    )
  )
}
