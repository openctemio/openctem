/**
 * Pure helpers of the remediation hub: tones, deadlines, the fix steps of an
 * action key, and grouping of task findings.
 */

import type { PillTone } from '@/features/shared/components/tone-pill'
import { upgradeCommands, type FixCommand } from '@/features/findings/lib/fix-guidance'
import type { RemediationSuggestion, RemediationTask, TaskMember, TaskState } from '../api/types'

export const STATE_TONE: Record<TaskState, PillTone> = {
  open: 'info',
  in_progress: 'warning',
  verifying: 'info',
  done: 'success',
  closed_unverified: 'muted',
  on_hold: 'muted',
  canceled: 'muted',
  archived: 'muted',
}

export type DeadlineStatus = 'none' | 'overdue' | 'due_soon' | 'on_track'

/** Overdue once past; due soon within three days. */
export function deadlineStatus(deadline: string | undefined, now = Date.now()): DeadlineStatus {
  if (!deadline) return 'none'
  const t = Date.parse(deadline)
  if (Number.isNaN(t)) return 'none'
  if (t < now) return 'overdue'
  if (t - now < 3 * 24 * 3600 * 1000) return 'due_soon'
  return 'on_track'
}

export const DEADLINE_TONE: Record<DeadlineStatus, PillTone> = {
  none: 'muted',
  overdue: 'destructive',
  due_soon: 'warning',
  on_track: 'success',
}

/** Share of a task's findings verified fixed, closed otherwise, and claimed fixed. */
export function progressParts(t: Pick<RemediationTask, 'counts'>) {
  const total = Math.max(t.counts.total, 0)
  if (total === 0) return { verified: 0, closed: 0, claimed: 0, open: 0, total: 0 }
  const verified = t.counts.verified
  const closed = Math.max(t.counts.closed - verified, 0)
  const claimed = t.counts.fix_applied
  const open = Math.max(total - verified - closed - claimed, 0)
  return { verified, closed, claimed, open, total }
}

export interface FixSteps {
  kind: string
  ecosystem?: string
  pkg?: string
  target?: string
  secretPrefix?: string
  commands: FixCommand[]
}

/** The fix a suggestion or an action key names, with the upgrade command. */
export function fixSteps(spec: Record<string, unknown> | undefined, key: string): FixSteps {
  const kind = String(spec?.kind ?? key.split(':')[0] ?? '')
  const str = (v: unknown) => (typeof v === 'string' ? v : undefined)
  if (kind === 'upgrade') {
    let ecosystem = str(spec?.ecosystem)
    let pkg = str(spec?.package)
    let target = str(spec?.target_version)
    if (!pkg) {
      const parts = key.split(':')
      if (parts.length === 4) {
        ecosystem = parts[1]
        pkg = parts[2].replaceAll('~', '/')
        target = parts[3]
      }
    }
    const commands = ecosystem && pkg && target ? upgradeCommands(ecosystem, pkg, target) : []
    return { kind, ecosystem, pkg, target, commands }
  }
  if (kind === 'rotate') {
    const prefix = str(spec?.secret_fingerprint_prefix) ?? key.split(':')[2]?.slice(0, 8)
    return { kind, secretPrefix: prefix, commands: [] }
  }
  return { kind, commands: [] }
}

/** Groups task findings by asset (findings without one last), keeping order. */
export function groupByAsset(
  members: TaskMember[]
): { key: string; label: string; items: TaskMember[] }[] {
  const groups = new Map<string, { key: string; label: string; items: TaskMember[] }>()
  for (const m of members) {
    const key = m.asset_id ?? ''
    let g = groups.get(key)
    if (!g) {
      g = { key, label: m.asset_name || '', items: [] }
      groups.set(key, g)
    }
    g.items.push(m)
  }
  return [...groups.values()].sort((a, b) => (a.key === '' ? 1 : b.key === '' ? -1 : 0))
}

/** A suggestion's risk parts as a short list ("P0 2 · P1 9"). */
export function riskPartsList(
  s: Pick<RemediationSuggestion, 'risk_parts'>
): { label: string; count: number }[] {
  const p = s.risk_parts
  if (!p) return []
  return [
    { label: 'P0', count: p.p0 },
    { label: 'P1', count: p.p1 },
    { label: 'P2', count: p.p2 },
    { label: 'P3', count: p.p3 },
  ].filter((x) => x.count > 0)
}

/** Whether a keyboard event comes from a field the person is typing in. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  const tag = target.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable
}
