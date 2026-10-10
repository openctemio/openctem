/**
 * Pure helpers of the scan approval rule editor (RFC-073 §4.1): which
 * conditions a rule sets, their chip labels, adding and removing one, and
 * reordering rules. The API validates every rule again on save.
 */

import type {
  ScanApprovalConditions,
  ScanApprovalRule,
  Weekday,
} from '@/lib/api/scan-approval-hooks'

type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** Condition kinds, in the order the editor offers them. */
export const CONDITION_KINDS = [
  'min_intensity',
  'tools',
  'asset_tags',
  'min_criticality',
  'crown_jewel',
  'dynamic_selectors',
  'targets_over',
  'cidr_wider_than',
  'recurring',
  'sensor_placement',
  'zone_ids',
  'requester_roles',
  'requester_group_ids',
  'origins',
  'trusted_service_account_ids',
  'hours',
] as const

export type ConditionKind = (typeof CONDITION_KINDS)[number]

export const WEEKDAYS: Weekday[] = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

/** The default value a newly added condition starts with. */
export function conditionDefault(kind: ConditionKind): ScanApprovalConditions {
  switch (kind) {
    case 'min_intensity':
      return { min_intensity: 'active' }
    case 'min_criticality':
      return { min_criticality: 'high' }
    case 'crown_jewel':
    case 'dynamic_selectors':
    case 'recurring':
      return { [kind]: true }
    case 'targets_over':
      return { targets_over: 500 }
    case 'cidr_wider_than':
      return { cidr_wider_than: 24 }
    case 'sensor_placement':
      return { sensor_placement: 'platform' }
    case 'origins':
      return { origins: ['api_key', 'service_account'] }
    case 'requester_roles':
      return { requester_roles: ['member'] }
    case 'hours':
      return {
        hours: {
          match: 'outside',
          windows: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri'], start: '09:00', end: '18:00' }],
        },
      }
    default:
      return { [kind]: [] }
  }
}

/** Whether conditions c set kind. */
export function hasCondition(c: ScanApprovalConditions, kind: ConditionKind): boolean {
  const v = c[kind]
  if (v === undefined || v === null || v === false || v === 0) return false
  return true
}

/** The kinds c sets, in editor order. */
export function activeConditions(c: ScanApprovalConditions): ConditionKind[] {
  return CONDITION_KINDS.filter((k) => hasCondition(c, k))
}

/** c with kind added at its default (kept when already set). */
export function addCondition(
  c: ScanApprovalConditions,
  kind: ConditionKind
): ScanApprovalConditions {
  if (hasCondition(c, kind)) return c
  return { ...c, ...conditionDefault(kind) }
}

/** c without kind. */
export function removeCondition(
  c: ScanApprovalConditions,
  kind: ConditionKind
): ScanApprovalConditions {
  const next = { ...c }
  delete next[kind]
  return next
}

function list(v: string[] | undefined, max = 3): string {
  const items = v ?? []
  if (items.length <= max) return items.join(', ')
  return `${items.slice(0, max).join(', ')} +${items.length - max}`
}

/** The chip label of one condition. names maps ids to display names. */
export function conditionLabel(
  t: T,
  c: ScanApprovalConditions,
  kind: ConditionKind,
  names: Record<string, string> = {}
): string {
  const named = (ids: string[] | undefined) => (ids ?? []).map((id) => names[id] ?? id.slice(0, 8))
  switch (kind) {
    case 'min_intensity':
      return t('scans.ruleEditor.chip.minIntensity', 'Intensity {value} or above', {
        value: t(`scans.ruleEditor.intensity.${c.min_intensity}`, c.min_intensity ?? ''),
      })
    case 'tools':
      return t('scans.ruleEditor.chip.tools', 'Tools: {value}', { value: list(c.tools) })
    case 'asset_tags':
      return t('scans.ruleEditor.chip.assetTags', 'Tagged: {value}', { value: list(c.asset_tags) })
    case 'min_criticality':
      return t('scans.ruleEditor.chip.minCriticality', 'Criticality {value} or above', {
        value: t(`scans.ruleEditor.criticality.${c.min_criticality}`, c.min_criticality ?? ''),
      })
    case 'crown_jewel':
      return t('scans.ruleEditor.chip.crownJewel', 'Crown jewels')
    case 'dynamic_selectors':
      return t('scans.ruleEditor.chip.dynamicSelectors', 'Wildcards or CIDRs')
    case 'targets_over':
      return t('scans.ruleEditor.chip.targetsOver', 'More than {value} targets', {
        value: c.targets_over ?? 0,
      })
    case 'cidr_wider_than':
      return t('scans.ruleEditor.chip.cidrWiderThan', 'CIDR wider than /{value}', {
        value: c.cidr_wider_than ?? 0,
      })
    case 'recurring':
      return t('scans.ruleEditor.chip.recurring', 'Scheduled scans')
    case 'sensor_placement':
      return c.sensor_placement === 'tenant'
        ? t('scans.ruleEditor.chip.placementTenant', 'Own sensors only')
        : t('scans.ruleEditor.chip.placementPlatform', 'Platform sensors may run it')
    case 'zone_ids':
      return t('scans.ruleEditor.chip.zones', 'Zones: {value}', {
        value: list(named(c.zone_ids)),
      })
    case 'requester_roles':
      return t('scans.ruleEditor.chip.requesterRoles', 'Requested by: {value}', {
        value: list(
          (c.requester_roles ?? []).map((r) =>
            names[r] ? names[r] : t(`scans.ruleEditor.role.${r}`, r)
          )
        ),
      })
    case 'requester_group_ids':
      return t('scans.ruleEditor.chip.requesterGroups', 'Requester in: {value}', {
        value: list(named(c.requester_group_ids)),
      })
    case 'origins':
      return t('scans.ruleEditor.chip.origins', 'Through: {value}', {
        value: list(
          (c.origins ?? []).map((o) => t(`scans.ruleEditor.origin.${o}`, o)),
          6
        ),
      })
    case 'trusted_service_account_ids':
      return t('scans.ruleEditor.chip.trusted', 'Except: {value}', {
        value: list(named(c.trusted_service_account_ids)),
      })
    case 'hours': {
      const h = c.hours
      const w = h?.windows?.[0]
      const span = w
        ? `${w.days.map((d) => t(`scans.ruleEditor.day.${d}`, d)).join(' ')} ${w.start}–${w.end}`
        : ''
      const more = (h?.windows?.length ?? 0) > 1 ? ` +${(h?.windows?.length ?? 1) - 1}` : ''
      return h?.match === 'inside'
        ? t('scans.ruleEditor.chip.hoursInside', 'During {value}', { value: span + more })
        : t('scans.ruleEditor.chip.hoursOutside', 'Outside {value}', { value: span + more })
    }
  }
}

/** rules with the rule at from moved to to. */
export function moveRule(rules: ScanApprovalRule[], from: number, to: number): ScanApprovalRule[] {
  if (from === to || from < 0 || to < 0 || from >= rules.length || to >= rules.length) return rules
  const next = rules.slice()
  const [r] = next.splice(from, 1)
  next.splice(to, 0, r)
  return next
}

/** A new, empty rule (the API assigns the id). */
export function newRule(): ScanApprovalRule {
  return {
    id: '',
    name: '',
    enabled: true,
    conditions: { min_intensity: 'intrusive' },
    requirement: { approvals: 1, validity: 'definition' },
  }
}

/** A "HH:MM" clock time (end may be 24:00). */
export function validClock(v: string, allow24 = false): boolean {
  if (!/^\d{2}:\d{2}$/.test(v)) return false
  const [h, m] = v.split(':').map(Number)
  if (allow24 && h === 24 && m === 0) return true
  return h < 24 && m < 60
}
