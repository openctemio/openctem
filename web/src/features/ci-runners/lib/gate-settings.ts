/**
 * Per-repository CI gate settings (api docs/rfcs/RFC-096-ci-per-repository-settings.md):
 * each gate field has an effective value, the layer it comes from and an
 * optional lock from a layer above. These helpers mirror the API's
 * "loosens" rules so the console offers only stricter values for a locked
 * field and asks for a reason before a change that loosens the gate. The API
 * stays the authority: it refuses a looser value under a lock (409) and a
 * loosening change without a reason (400).
 */

import type { CIGatePolicy, CIGatePolicyRequest } from '../types'

/** Gate policy fields, in the API's display order. */
export const GATE_FIELDS = [
  'mode',
  'fail_on_severity',
  'new_findings_only',
  'fail_on_kev',
  'epss_threshold',
  'fixable_only',
  'modes',
  'allow_repo_policy',
  'baseline_on_first_run',
  'baseline_grace_days',
  'baseline_secrets_block',
] as const
export type GateField = (typeof GATE_FIELDS)[number]

export function isGateField(f: string | undefined): f is GateField {
  return !!f && (GATE_FIELDS as readonly string[]).includes(f)
}

/** English labels; the console translates them as scans.ci.gateField.<field>. */
export const GATE_FIELD_LABEL: Record<GateField, string> = {
  mode: 'Mode',
  fail_on_severity: 'Fail on severity',
  new_findings_only: 'New findings only',
  fail_on_kev: 'Known exploited (KEV) fails',
  epss_threshold: 'EPSS threshold',
  fixable_only: 'Block only fixable vulnerabilities',
  modes: 'Finding modes',
  allow_repo_policy: 'Allow .openctem.yml',
  baseline_on_first_run: 'Baseline on first run',
  baseline_grace_days: 'Baseline grace (days)',
  baseline_secrets_block: 'Secrets in the baseline block',
}

/** Layers a value can come from; translated as scans.ci.gateSource.<source>. */
export const GATE_SOURCE_LABEL: Record<string, string> = {
  default: 'Default',
  tenant: 'Organization',
  business_unit: 'Business unit',
  repository: 'This repository',
}

export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical', 'none'] as const
/** Capabilities a finding mode can be set for (api cirun.modeCapabilities). */
export const MODE_CAPABILITIES = ['sast', 'sca', 'secrets', 'iac', 'container'] as const
export const FINDING_MODES = ['block', 'comment', 'monitor'] as const

export interface PolicyModes {
  capabilities?: Record<string, string>
  rules?: Record<string, string>
}

/** A field's value as the API sends it. */
export type GateValue = string | number | boolean | null | PolicyModes | undefined

const BOOLEAN_STRICT_WHEN: Partial<Record<GateField, boolean>> = {
  new_findings_only: false,
  fail_on_kev: true,
  fixable_only: false,
  baseline_on_first_run: false,
  baseline_secrets_block: true,
}

export function isBooleanField(f: GateField): boolean {
  return f in BOOLEAN_STRICT_WHEN || f === 'allow_repo_policy'
}

function severityRank(s: unknown): number {
  const order: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 }
  return typeof s === 'string' && s in order ? order[s] : 99
}

const MODE_RANK: Record<string, number> = { block: 3, comment: 2, monitor: 1 }
function modeRank(m: string | undefined): number {
  return m ? (MODE_RANK[m] ?? 0) : 0
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

/** Mirrors the API's modesLoosen: unset means block. */
function modesLoosen(
  before: PolicyModes | null | undefined,
  after: PolicyModes | null | undefined
) {
  const b = before ?? {}
  const a = after ?? {}
  const cap = (m: PolicyModes, c: string) =>
    m.capabilities && c in m.capabilities ? modeRank(m.capabilities[c]) : MODE_RANK.block
  if (MODE_CAPABILITIES.some((c) => cap(a, c) < cap(b, c))) return true
  const weakest = Math.min(...MODE_CAPABILITIES.map((c) => cap(a, c)))
  for (const [r, v] of Object.entries(a.rules ?? {})) {
    const was = b.rules?.[r]
    if (was === undefined) {
      if (modeRank(v) < MODE_RANK.block) return true
    } else if (modeRank(v) < modeRank(was)) return true
  }
  for (const [r, was] of Object.entries(b.rules ?? {})) {
    if (!(r in (a.rules ?? {})) && weakest < modeRank(was)) return true
  }
  return false
}

/**
 * Whether taking `next` instead of `base` for field `f` lets more findings
 * pass (the API's cirun.Loosens, one field at a time).
 */
export function fieldLoosens(f: GateField, base: GateValue, next: GateValue): boolean {
  switch (f) {
    case 'mode':
      return base === 'enforce' && next !== 'enforce'
    case 'fail_on_severity':
      return severityRank(next) > severityRank(base)
    case 'epss_threshold':
    case 'baseline_grace_days': {
      const b = num(base)
      const n = num(next)
      return b !== null && (n === null || n > b)
    }
    case 'modes':
      return modesLoosen(base as PolicyModes, next as PolicyModes)
    case 'allow_repo_policy':
      return false
    default: {
      const strict = BOOLEAN_STRICT_WHEN[f]
      return strict !== undefined && base === strict && next !== strict
    }
  }
}

/**
 * The values the editor may offer for a select or switch field: every value
 * when unlocked; when locked, only those that do not loosen what is inherited.
 */
export function allowedOptions(
  f: GateField,
  inherited: GateValue,
  locked: boolean
): (string | boolean)[] {
  const all: (string | boolean)[] =
    f === 'mode'
      ? ['enforce', 'warn']
      : f === 'fail_on_severity'
        ? [...SEVERITY_ORDER]
        : isBooleanField(f)
          ? [true, false]
          : []
  return locked ? all.filter((v) => !fieldLoosens(f, inherited, v)) : all
}

/** The modes a locked capability may take (never weaker than inherited). */
export function allowedCapabilityModes(
  inherited: PolicyModes | null | undefined,
  capability: string,
  locked: boolean
): string[] {
  if (!locked) return [...FINDING_MODES]
  const was = inherited?.capabilities?.[capability] ?? 'block'
  return FINDING_MODES.filter((m) => modeRank(m) >= modeRank(was))
}

/** Keys of the request body that carry a field's value. */
function valueBody(f: GateField, v: GateValue): Partial<CIGatePolicyRequest> {
  switch (f) {
    case 'epss_threshold':
    case 'baseline_grace_days':
      return { [f]: num(v) ?? undefined }
    case 'modes':
      return { modes: (v ?? {}) as CIGatePolicyRequest['modes'] }
    default:
      return { [f]: v as never }
  }
}

/**
 * The current values of a repository policy as a full request body. A PATCH
 * replaces reason, expires_at, epss_threshold and baseline_grace_days on
 * every write, so every write starts from this.
 */
export function policyBody(p: CIGatePolicy): CIGatePolicyRequest {
  return {
    mode: p.mode,
    fail_on_severity: p.fail_on_severity,
    new_findings_only: p.new_findings_only,
    fail_on_kev: p.fail_on_kev,
    epss_threshold: p.epss_threshold ?? undefined,
    fixable_only: p.fixable_only,
    modes: p.modes,
    allow_repo_policy: p.allow_repo_policy,
    baseline_on_first_run: p.baseline_on_first_run,
    baseline_grace_days: p.baseline_grace_days ?? undefined,
    baseline_secrets_block: p.baseline_secrets_block,
    fields: [...(p.fields ?? [])],
    reason: p.reason || undefined,
    expires_at: p.expires_at || undefined,
  }
}

export interface EffectiveField {
  field?: string
  value?: unknown
  inherited?: unknown
  source?: string
  policy_id?: string
  locked_by?: string
  ignored?: boolean
}

/** Field values as a body, from the effective settings (a new policy starts here). */
export function effectiveBody(fields: EffectiveField[]): CIGatePolicyRequest {
  let body: CIGatePolicyRequest = {}
  for (const f of fields) {
    if (isGateField(f.field)) body = { ...body, ...valueBody(f.field, f.value as GateValue) }
  }
  return body
}

function inOrder(fields: string[]): string[] {
  return GATE_FIELDS.filter((f) => fields.includes(f))
}

export interface OverrideMeta {
  reason?: string
  /** ISO time or undefined for no end. */
  expiresAt?: string
  /**
   * Fields the repository sets but a lock above ignores (looser than the
   * lock allows). They leave `fields` on any write: the API refuses to store
   * a looser value under a lock, so keeping them would refuse every change.
   */
  dropped?: string[]
}

/**
 * The write that overrides field `f` with `value` for a repository: a PATCH
 * of its policy when it has one, else a POST of a new repository policy that
 * sets only this field.
 */
export function overrideWrite(
  repositoryAssetId: string,
  repo: CIGatePolicy | undefined,
  effective: EffectiveField[],
  f: GateField,
  value: GateValue,
  meta: OverrideMeta
): { id?: string; body: CIGatePolicyRequest } {
  const base = repo?.id ? policyBody(repo) : effectiveBody(effective)
  const kept = (repo?.id ? (repo.fields ?? []) : []).filter((x) => !meta.dropped?.includes(x))
  const fields = inOrder([...new Set([...kept, f])])
  const body: CIGatePolicyRequest = {
    ...base,
    ...valueBody(f, value),
    fields,
    reason: meta.reason?.trim() || undefined,
    expires_at: meta.expiresAt || undefined,
  }
  if (!repo?.id) return { body: { ...body, scope_type: 'repository', scope_id: repositoryAssetId } }
  return { id: repo.id, body }
}

/**
 * Reset field `f` to what the repository inherits: the field leaves the
 * policy's `fields`; with no field left the policy is deleted.
 */
export function resetWrite(
  repo: CIGatePolicy,
  f: GateField,
  meta: OverrideMeta
): { kind: 'delete'; id: string } | { kind: 'patch'; id: string; body: CIGatePolicyRequest } {
  const fields = (repo.fields ?? []).filter((x) => x !== f && !meta.dropped?.includes(x))
  if (fields.length === 0) return { kind: 'delete', id: repo.id ?? '' }
  return {
    kind: 'patch',
    id: repo.id ?? '',
    body: {
      ...policyBody(repo),
      fields,
      reason: meta.reason?.trim() || undefined,
      expires_at: meta.expiresAt || undefined,
    },
  }
}

export const MIN_REASON = 10
export const MAX_REASON = 500
export const MAX_OVERRIDE_DAYS = 365

export function validReason(r: string): boolean {
  const n = r.trim().length
  return n >= MIN_REASON && n <= MAX_REASON
}

/** Whether an end date (yyyy-mm-dd) is in the future and within 365 days of now. */
export function validEndDate(d: string, now: Date = new Date()): boolean {
  if (!d) return true
  const t = new Date(`${d}T23:59:59Z`).getTime()
  if (Number.isNaN(t)) return false
  return t > now.getTime() && t - now.getTime() <= MAX_OVERRIDE_DAYS * 86_400_000
}

/** An end date (yyyy-mm-dd) as the ISO time the API takes (end of that day, UTC). */
export function endDateISO(d: string): string | undefined {
  return d ? new Date(`${d}T23:59:59Z`).toISOString() : undefined
}

/** When baseline findings block again: set_at plus the grace days (null: no end). */
export function baselineDueAt(setAt: string | undefined, graceDays: unknown): Date | null {
  const g = num(graceDays)
  if (!setAt || g === null) return null
  const t = new Date(setAt).getTime()
  return Number.isNaN(t) ? null : new Date(t + g * 86_400_000)
}

/** Whether a 400 from a policy write asks for a reason (a loosening change). */
export function needsReasonError(message: string | undefined): boolean {
  return !!message && /needs a reason/i.test(message)
}

/** Whether a decoration detail says no code-host connection exists for the repository. */
export function missingCodeHost(detail: string | undefined): 'gitlab' | 'github' | null {
  if (!detail) return null
  if (/^no GitLab connection/i.test(detail)) return 'gitlab'
  if (/^no GitHub App installation/i.test(detail)) return 'github'
  return null
}

/** Attempt labels for runs of the same commit of the same pipeline (retries). */
export function runAttempts<
  R extends {
    id?: string
    pipeline_id?: string
    repository?: string
    workflow?: string
    commit_sha?: string
    created_at?: string
  },
>(runs: R[]): Map<string, { attempt: number; of: number }> {
  const groups = new Map<string, R[]>()
  for (const r of runs) {
    if (!r.id || !r.commit_sha) continue
    const key = `${r.pipeline_id || `${r.repository}|${r.workflow}`}|${r.commit_sha}`
    groups.set(key, [...(groups.get(key) ?? []), r])
  }
  const out = new Map<string, { attempt: number; of: number }>()
  for (const list of groups.values()) {
    if (list.length < 2) continue
    const sorted = [...list].sort((a, b) => (a.created_at ?? '').localeCompare(b.created_at ?? ''))
    sorted.forEach((r, i) => out.set(r.id ?? '', { attempt: i + 1, of: sorted.length }))
  }
  return out
}

/**
 * A run's baseline split: findings known in the repository's gate baseline
 * (not blocking) and new ones, when a baseline was recorded; null otherwise
 * (the summary then says "already on <branch>").
 */
export function baselineCounts(
  v:
    | {
        summary?: { new?: number; pre_existing?: number }
        baseline?: { set_at?: string }
      }
    | undefined
): { baseline: number; fresh: number } | null {
  if (!v?.baseline?.set_at || !v.summary) return null
  return { baseline: v.summary.pre_existing ?? 0, fresh: v.summary.new ?? 0 }
}
