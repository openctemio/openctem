/**
 * How we found this (api docs/architecture/exploration.md): a short ordered
 * chain read from GET /api/v1/findings/{id}/story or
 * GET /api/v1/assets/{id}/story, scope entry first and the subject last. A
 * step the viewer may not see arrives with `hidden` set and no identifying
 * field; the page shows it as a step you cannot see.
 */
import type { TFn } from '@/features/assets/lib/default-t'
import { assetDetailHref } from '@/features/findings/lib/asset-link'

export type StoryStepKind = 'scope_entry' | 'asset' | 'scan' | 'report' | 'finding'

export interface StoryAsset {
  id?: string
  name?: string
  type?: string
  /** How this asset leads to the next one down the chain. Kept when hidden. */
  via?: string
  discovery_source?: string
  discovery_tool?: string
  subject?: boolean
}

export interface StoryScopeEntry {
  id: string
  target_type: string
  pattern: string
  asset_id: string
  excluded_by?: string
}

export interface StoryScan {
  role: 'discovered' | 'scanned' | 'reported' | string
  run_id: string
  scan_id?: string
  scan_name?: string
  run_status?: string
  step_run_id?: string
  step_name?: string
  capability?: string
  tool?: string
  relation?: string
}

export interface StoryReport {
  channel: string
  tool?: string
  tool_version?: string
  sensor?: { id: string; name?: string }
  sender?: string
  receipt_id?: string
  first_seen_at: string
  last_seen_at: string
  seen_count: number
  backfilled: boolean
}

export interface StoryStep {
  kind: StoryStepKind
  hidden: boolean
  at?: string
  asset?: StoryAsset
  scope_entry?: StoryScopeEntry
  scan?: StoryScan
  report?: StoryReport
  finding?: { id: string; title: string }
}

export interface Story {
  subject: { kind: 'finding' | 'asset'; id: string }
  steps: StoryStep[]
  hidden: number
  truncated: boolean
  more_reports: number
  first_seen_at?: string
  last_seen_at?: string
  max_steps: number
}

/** The URL of a subject's story. */
export function storyUrl(kind: 'finding' | 'asset', id: string): string {
  return `/api/v1/${kind === 'finding' ? 'findings' : 'assets'}/${encodeURIComponent(id)}/story`
}

/** What a step did, in a few words: the label shown before its name. */
export function stepRoleLabel(t: TFn, step: StoryStep): string {
  if (step.hidden) return t('exploration.story.hidden', 'A step you cannot see')
  switch (step.kind) {
    case 'scope_entry':
      return t('exploration.story.role.scope', 'In scope by')
    case 'asset':
      return step.asset?.subject
        ? t('exploration.story.role.subjectAsset', 'This asset')
        : t('exploration.story.role.asset', 'Found under')
    case 'scan':
      switch (step.scan?.role) {
        case 'discovered':
          return t('exploration.story.role.discovered', 'Discovered by')
        case 'scanned':
          return t('exploration.story.role.scanned', 'Last scanned by')
        default:
          return t('exploration.story.role.scanReported', 'Scanned by')
      }
    case 'report':
      return t('exploration.story.role.reported', 'Reported by')
    case 'finding':
      return t('exploration.story.role.finding', 'Finding')
  }
  return ''
}

/** Why a hidden step is hidden, for its hint. */
export function hiddenHint(t: TFn, kind: StoryStepKind): string {
  if (kind === 'scan')
    return t('exploration.story.hiddenScan', 'A scan run: you need permission to view scans.')
  return t('exploration.story.hiddenAsset', 'An asset outside your data scope.')
}

/** Where a step links to; undefined when it has no page. */
export function stepHref(step: StoryStep): string | undefined {
  if (step.hidden) return undefined
  if (step.asset?.id && !step.asset.subject) return assetDetailHref(step.asset.id)
  if (step.scope_entry?.pattern)
    return `/scope?tab=in&q=${encodeURIComponent(step.scope_entry.pattern)}`
  if (step.scan?.run_id) return `/scans/runs?run=${encodeURIComponent(step.scan.run_id)}`
  return undefined
}

/** True when nothing but the subject is known: the chain says nothing. */
export function storyIsEmpty(story: Story | undefined): boolean {
  if (!story) return true
  return !story.steps.some((s) => s.hidden || (s.kind !== 'finding' && !s.asset?.subject))
}
