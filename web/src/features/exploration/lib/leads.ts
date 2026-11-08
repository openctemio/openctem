/**
 * Exploration leads (api docs/architecture/exploration.md, "Approvals and
 * people" and "Rollups"): the next steps the platform plans on an asset, read
 * from GET /api/v1/exploration/leads and /summary. Pure helpers: wire types,
 * request URLs and the labels the page and the asset card share.
 */
import type { TFn } from '@/features/assets/lib/default-t'
import { ApiClientError } from '@/lib/api/error-handler'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { leadTypeKey } from './lead-types.generated'

export type LeadState =
  | 'proposed'
  | 'awaiting_approval'
  | 'open'
  | 'running'
  | 'blocked'
  | 'done'
  | 'refuted'
  | 'exhausted'
  | 'dismissed'
  | 'superseded'

export type LeadOrigin = 'rule' | 'user' | 'ai_agent' | 'system'

export interface LeadScoreInputs {
  p_useful?: number
  value?: number
  cost_seconds?: number
  tried?: number
  useful?: number
  demoted?: boolean
}

export interface Lead {
  id: string
  type: string
  state: LeadState | string
  capability: string
  /** 0 passive, 1 active, 2 intrusive. */
  tier: number
  subject_asset_id?: string
  reason_code: string
  /** Free text from a rule, a person or an AI: always rendered as text. */
  rationale: string
  origin: LeadOrigin | string
  likelihood: string
  score: number
  score_inputs?: LeadScoreInputs | null
  blocked_reason?: string
  attempts: number
  next_attempt_at?: string
  approved_at?: string
  approved_by?: string
  created_at: string
  updated_at: string
  closed_at?: string
}

export type LeadLinkRel = 'derived_from' | 'dispatched_as' | 'yields'
export type LeadLinkEnd = 'asset' | 'finding' | 'scan_run' | 'lead'

export interface LeadLink {
  rel: LeadLinkRel | string
  end_kind: LeadLinkEnd | string
  end_id?: string
  effect?: string
  outcome_reason?: string
  created_at: string
}

export interface LeadVerdict {
  verdict: 'proven' | 'refuted' | 'inconclusive' | string
  tier: 'deterministic' | 'human' | 'heuristic' | 'ai' | string
  checker: string
  evidence: { kind: string; id: string; sha256?: string }[] | null
  reason: string
  created_at: string
}

export interface LeadDetail extends Lead {
  links: LeadLink[] | null
  verdicts: LeadVerdict[] | null
}

export interface LeadPage {
  data: Lead[] | null
  next_before?: string
}

export interface LeadSummary {
  open: number
  awaiting_approval: number
  running: number
  blocked: number
  done_30d: number
  proven_30d: number
  refuted_30d: number
  dispatches_30d: number
  rule_share?: number
  median_verdict_seconds?: number
  last_step_at?: string
  computed_at?: string
  scope: 'organization' | 'mine' | string
}

export interface LeadBulkResult {
  id: string
  ok: boolean
  error?: 'not_found' | 'wrong_state' | 'changed' | string
}

export const LEAD_GROUPS = ['waiting', 'next', 'running', 'done'] as const
export type LeadGroup = (typeof LEAD_GROUPS)[number]

export const LEADS_PAGE_SIZE = 50

export function isLeadGroup(v: string): v is LeadGroup {
  return (LEAD_GROUPS as readonly string[]).includes(v)
}

export const LEADS_URL = '/api/v1/exploration/leads'
export const SUMMARY_URL = '/api/v1/exploration/summary'

/** GET /exploration/leads for one group, one asset or both, from `before` (keyset). */
export function leadsUrl(q: {
  group?: LeadGroup
  assetId?: string
  before?: string
  limit?: number
}): string {
  const p = new URLSearchParams()
  if (q.group) p.set('group', q.group)
  if (q.assetId) p.set('asset_id', q.assetId)
  if (q.before) p.set('before', q.before)
  if (q.limit) p.set('limit', String(q.limit))
  const s = p.toString()
  return s ? `${LEADS_URL}?${s}` : LEADS_URL
}

export function leadUrl(id: string): string {
  return `${LEADS_URL}/${encodeURIComponent(id)}`
}

/** The page's own link, optionally for one asset. */
export function explorationHref(assetId?: string): string {
  return assetId ? `/exploration?asset=${encodeURIComponent(assetId)}` : '/exploration'
}

/** States a person may still approve (the API refuses the rest per lead). */
export function canApproveLead(l: Pick<Lead, 'state'>): boolean {
  return l.state === 'awaiting_approval' || l.state === 'proposed'
}

/** States a person may still dismiss: every live state. */
export function canDismissLead(l: Pick<Lead, 'state'>): boolean {
  return ['proposed', 'awaiting_approval', 'open', 'running', 'blocked'].includes(l.state)
}

export function isClosedLead(l: Pick<Lead, 'state'>): boolean {
  return !canDismissLead(l)
}

export type TierKey = 'passive' | 'active' | 'intrusive'

export function tierKey(tier: number): TierKey {
  if (tier <= 0) return 'passive'
  if (tier === 1) return 'active'
  return 'intrusive'
}

export function tierLabel(t: TFn, tier: number): string {
  switch (tierKey(tier)) {
    case 'passive':
      return t('exploration.tier.passive', 'Passive')
    case 'active':
      return t('exploration.tier.active', 'Active')
    default:
      return t('exploration.tier.intrusive', 'Intrusive')
  }
}

/** The lead type's short name ("Takeover check"); the raw id when unknown. */
export function leadTitle(t: TFn, type: string): string {
  return t(`exploration.leadTypes.${leadTypeKey(type)}.title`, type)
}

/** The question the lead asks, in plain words. */
export function leadQuestion(t: TFn, type: string): string {
  return t(`exploration.leadTypes.${leadTypeKey(type)}.question`, type)
}

/** Why the lead was opened (its reason code); the raw code when unknown. */
export function reasonLabel(t: TFn, code: string): string {
  if (!code) return ''
  return t(`exploration.reasons.${code}`, code)
}

const BLOCKED_CODES = [
  'out_of_scope',
  'excluded',
  'intrusive_needs_person',
  'no_action_for_subject',
  'refused',
] as const

/** Why a lead is blocked; a code the console does not know is shown as given. */
export function blockedReasonLabel(t: TFn, code: string | undefined): string {
  if (!code) return ''
  if ((BLOCKED_CODES as readonly string[]).includes(code)) {
    return t(`exploration.blocked.${code}`, code)
  }
  return t('exploration.blocked.other', 'Refused by a check ({code})', { code })
}

/** A state in a few words ("Waiting for approval", "Nothing found"). */
export function stateLabel(t: TFn, state: string): string {
  switch (state) {
    case 'proposed':
      return t('exploration.state.proposed', 'Suggested')
    case 'awaiting_approval':
      return t('exploration.state.awaiting_approval', 'Waiting for approval')
    case 'open':
      return t('exploration.state.open', 'Scheduled')
    case 'running':
      return t('exploration.state.running', 'Running')
    case 'blocked':
      return t('exploration.state.blocked', 'Blocked')
    case 'done':
      return t('exploration.state.done', 'Confirmed')
    case 'refuted':
      return t('exploration.state.refuted', 'Nothing found')
    case 'exhausted':
      return t('exploration.state.exhausted', 'No answer')
    case 'dismissed':
      return t('exploration.state.dismissed', 'Dismissed')
    case 'superseded':
      return t('exploration.state.superseded', 'No longer needed')
  }
  return state
}

export type StateTone = 'success' | 'warning' | 'destructive' | 'info' | 'muted'

export function stateTone(state: string): StateTone {
  switch (state) {
    case 'proposed':
    case 'awaiting_approval':
      return 'warning'
    case 'open':
    case 'running':
      return 'info'
    case 'blocked':
      return 'destructive'
    case 'done':
      return 'success'
    default:
      return 'muted'
  }
}

/**
 * The state as the asset card says it: "Waiting for approval", "Scheduled",
 * "Running", "Blocked: out of scope", or for a closed lead its outcome and
 * date ("Done: nothing found, 3 Nov 2026").
 */
export function leadStatusText(t: TFn, l: Lead, formatDate: (iso: string) => string): string {
  if (l.state === 'blocked' && l.blocked_reason) {
    return t('exploration.status.blocked', 'Blocked: {reason}', {
      reason: blockedReasonLabel(t, l.blocked_reason),
    })
  }
  if (isClosedLead(l)) {
    const when = l.closed_at ?? l.updated_at
    return t('exploration.status.closed', 'Done: {outcome}, {date}', {
      outcome: stateLabel(t, l.state).toLowerCase(),
      date: formatDate(when),
    })
  }
  return stateLabel(t, l.state)
}

/**
 * The page's opening sentence: "14 next steps, 3 waiting for your approval,
 * last step 5 minutes ago". Parts with nothing to say are left out.
 */
export function statusSentence(
  t: TFn,
  s: LeadSummary,
  relativeTime: (iso: string) => string
): string {
  const parts: string[] = [
    t('exploration.summary.next', '{count, plural, one {# next step} other {# next steps}}', {
      count: s.open,
    }),
  ]
  if (s.awaiting_approval > 0) {
    parts.push(
      t('exploration.summary.waiting', '{count} waiting for your approval', {
        count: s.awaiting_approval,
      })
    )
  }
  if (s.running > 0) {
    parts.push(t('exploration.summary.running', '{count} running', { count: s.running }))
  }
  if (s.blocked > 0) {
    parts.push(t('exploration.summary.blocked', '{count} blocked', { count: s.blocked }))
  }
  parts.push(
    s.last_step_at
      ? t('exploration.summary.lastStep', 'last step {time}', {
          time: relativeTime(s.last_step_at),
        })
      : t('exploration.summary.noStepYet', 'no step taken yet')
  )
  return parts.join(', ')
}

/** Links grouped by relation, in the order a reader follows them. */
export function groupLinks(links: LeadLink[] | null | undefined): [string, LeadLink[]][] {
  const order = ['derived_from', 'dispatched_as', 'yields']
  const map = new Map<string, LeadLink[]>()
  for (const l of links ?? []) {
    const list = map.get(l.rel) ?? []
    list.push(l)
    map.set(l.rel, list)
  }
  return [...map.entries()].sort(
    ([a], [b]) =>
      (order.indexOf(a) < 0 ? 99 : order.indexOf(a)) -
      (order.indexOf(b) < 0 ? 99 : order.indexOf(b))
  )
}

export function linkRelLabel(t: TFn, rel: string): string {
  switch (rel) {
    case 'derived_from':
      return t('exploration.links.derived_from', 'Came from')
    case 'dispatched_as':
      return t('exploration.links.dispatched_as', 'Ran as')
    case 'yields':
      return t('exploration.links.yields', 'Produced')
  }
  return rel
}

export function linkEndLabel(t: TFn, kind: string): string {
  switch (kind) {
    case 'asset':
      return t('exploration.links.end.asset', 'Asset')
    case 'finding':
      return t('exploration.links.end.finding', 'Finding')
    case 'scan_run':
      return t('exploration.links.end.scan_run', 'Scan run')
    case 'lead':
      return t('exploration.links.end.lead', 'Another step')
  }
  return kind
}

export function effectLabel(t: TFn, effect: string | undefined): string {
  if (!effect) return ''
  return t(`exploration.links.effect.${effect}`, effect)
}

/** Where a link's end opens; undefined for a lead (opened in place) or no id. */
export function linkHref(l: LeadLink): string | undefined {
  if (!l.end_id) return undefined
  switch (l.end_kind) {
    case 'asset':
      return isLinkableAssetId(l.end_id) ? assetDetailHref(l.end_id) : undefined
    case 'finding':
      return `/findings/${encodeURIComponent(l.end_id)}`
    case 'scan_run':
      return `/scans/runs?run=${encodeURIComponent(l.end_id)}`
  }
  return undefined
}

export function verdictLabel(t: TFn, verdict: string): string {
  switch (verdict) {
    case 'proven':
      return t('exploration.verdict.proven', 'Proven')
    case 'refuted':
      return t('exploration.verdict.refuted', 'Refuted')
    case 'inconclusive':
      return t('exploration.verdict.inconclusive', 'Inconclusive')
  }
  return verdict
}

/** Who answered: a check, a person, a heuristic or an AI (never shown as proof). */
export function verdictTierLabel(t: TFn, tier: string): string {
  switch (tier) {
    case 'deterministic':
      return t('exploration.verdict.tier.deterministic', 'Checked by a scan')
    case 'human':
      return t('exploration.verdict.tier.human', 'Decided by a person')
    case 'heuristic':
      return t('exploration.verdict.tier.heuristic', 'Heuristic, not verified')
    case 'ai':
      return t('exploration.verdict.tier.ai', 'AI suggestion, not verified')
  }
  return tier
}

export function originLabel(t: TFn, origin: string): string {
  switch (origin) {
    case 'rule':
      return t('exploration.origin.rule', 'A rule')
    case 'user':
      return t('exploration.origin.user', 'A person')
    case 'ai_agent':
      return t('exploration.origin.ai_agent', 'An AI agent')
    case 'system':
      return t('exploration.origin.system', 'The platform')
  }
  return origin
}

/** A score as a share of the highest score on the page, 0..1. */
export function scoreShare(score: number, max: number): number {
  if (!(max > 0) || !(score > 0)) return 0
  return Math.min(1, score / max)
}

/** Ids of the selected leads that may still be approved. */
export function approvableIds(leads: Lead[], selected: ReadonlySet<string>): string[] {
  return leads.filter((l) => selected.has(l.id) && canApproveLead(l)).map((l) => l.id)
}

/** How a bulk answer went: how many changed, and how many the API refused. */
export function bulkOutcome(results: LeadBulkResult[] | null | undefined): {
  ok: number
  failed: number
} {
  const list = results ?? []
  const ok = list.filter((r) => r.ok).length
  return { ok, failed: list.length - ok }
}

/** What went wrong when asking a question, in words that name the fix. */
export function askErrorMessage(t: TFn, err: unknown): string {
  if (err instanceof ApiClientError) {
    switch (err.statusCode) {
      case 400:
        return t(
          'exploration.ask.error.notApplicable',
          'This question does not apply to this kind of asset. Choose another question.'
        )
      case 403:
        return t('exploration.ask.error.forbidden', 'You need permission to run scans to ask.')
      case 404:
        return t('exploration.ask.error.notFound', 'This asset is no longer in your scope.')
      case 409:
        return t(
          'exploration.ask.error.conflict',
          'This question is already open for this asset, or too many questions are open. See the Exploration page.'
        )
    }
  }
  return t('exploration.ask.error.generic', 'Could not ask the question. Try again.')
}
