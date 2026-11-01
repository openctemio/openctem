/**
 * Attack surface > Discovery: the organization's coverage work in four
 * stages (GET /api/v1/attack-surface/discovery). Types mirror the API's
 * DiscoveryOverviewResponse; the CSV has the same columns as the API export.
 */

import { buildCsv } from '@/hooks/use-csv-export'

export const DISCOVERY_URL = '/api/v1/attack-surface/discovery'

export const DISCOVERY_STAGES = [
  'asset_discovery',
  'exposure_scan',
  'validation_scoping',
  'technology_discovery',
] as const
export type DiscoveryStage = (typeof DISCOVERY_STAGES)[number]

export type DiscoveryStatus = 'idle' | 'running' | 'paused' | 'failed'

export interface DiscoveryRun {
  id: string
  status: string
  created_at: string
  started_at?: string
  completed_at?: string
  tasks_total: number
  tasks_done: number
}

export interface DiscoveryCapability {
  capability: string
  pairs: number
  covered: number
  due_now: number
  queued: number
  failed: number
  blocked: number
  paused: number
  paused_reason?: string
  last_attempt_at?: string
  last_success_at?: string
  last_run?: DiscoveryRun
}

export interface DiscoveryStageRow {
  stage: DiscoveryStage
  status: DiscoveryStatus
  reason?: string
  last_run_at?: string
  progress_done: number
  progress_total: number
  progress_unit: 'tasks' | 'pairs'
  run_available_at?: string
  auto_validated_assets?: number
  capabilities: DiscoveryCapability[]
}

export interface DiscoveryOverview {
  generated_at: string
  loop_enabled: boolean
  coverage_enabled: boolean
  pass_every_seconds: number
  daily_budget: number
  budget_used: number
  auto_validation: { assets: number; window_start?: string; window_end?: string }
  stages: DiscoveryStageRow[]
}

export interface DiscoveryRunResult {
  started: DiscoveryStage[]
  skipped: DiscoveryStage[]
  capabilities: string[]
  pairs_made_due: number
  next_pass_within_seconds: number
}

export interface DiscoveryAbortResult {
  canceled: number
  failed: number
}

export function stageRunUrl(stage: DiscoveryStage): string {
  return `${DISCOVERY_URL}/stages/${stage}/run`
}

export function isDiscoveryStage(v: string): v is DiscoveryStage {
  return (DISCOVERY_STAGES as readonly string[]).includes(v)
}

/** Whether Run is held back by the once-a-minute limit at `now`. */
export function runLimited(row: DiscoveryStageRow, now: number = Date.now()): boolean {
  return !!row.run_available_at && Date.parse(row.run_available_at) > now
}

/** Whether any stage has an active coverage run (Abort all has something to do). */
export function anyRunning(o: DiscoveryOverview | undefined): boolean {
  return !!o?.stages.some((s) => s.status === 'running')
}

/** The export: one row per stage and capability, the API export's columns. */
export function discoveryCsv(o: DiscoveryOverview): string {
  const rows: (string | number)[][] = []
  for (const s of o.stages) {
    for (const c of s.capabilities) {
      rows.push([
        s.stage,
        s.status,
        s.reason ?? '',
        c.capability,
        c.pairs,
        c.covered,
        c.due_now,
        c.queued,
        c.failed,
        c.blocked,
        c.paused,
        c.paused_reason ?? '',
        c.last_attempt_at ?? '',
        c.last_success_at ?? '',
        c.last_run?.status ?? '',
        c.last_run?.started_at ?? '',
        c.last_run?.completed_at ?? '',
      ])
    }
  }
  return buildCsv(
    [
      'stage',
      'stage_status',
      'stage_reason',
      'capability',
      'pairs',
      'covered',
      'due_now',
      'queued',
      'failed',
      'blocked',
      'paused',
      'paused_reason',
      'last_attempt_at',
      'last_success_at',
      'last_run_status',
      'last_run_started_at',
      'last_run_completed_at',
    ],
    rows
  )
}
