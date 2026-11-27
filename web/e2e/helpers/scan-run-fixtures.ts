/**
 * Synthetic scan runs for the phone card specs: every run status the API
 * stores (scanrun.RunStatus, SCAN_RUN_STATUSES) and every optional field
 * absent and present. No live data: names and messages are made up, shaped
 * like the messages the server writes (scanrun/run.go: partial and failed
 * runs carry an error_message).
 */

/** Every status the API stores for a run, in the order of the Status filter. */
export const RUN_STATUSES = [
  'pending',
  'running',
  'completed',
  'partial',
  'failed',
  'timeout',
  'canceled',
  'blocked',
] as const

const LONG_NAME = 'External perimeter recon for every production hostname of the payments platform'
const PARTIAL_MESSAGE = 'Scan run completed partially: 2 of 6 steps did not finish all their work'
const FAILED_MESSAGE =
  'Scan workflow failed: Step "nuclei-dast" failed: sensor reported exit status 2 after 3 attempts: ' +
  'template-load: /opt/templates/http/misconfiguration/some-very-long-template-file-name-without-spaces.yaml ' +
  '(TOOL_EXIT_NONZERO)'
const UNBROKEN_MESSAGE = `upstream=${'x'.repeat(220)}`

let seq = 0
function id(): string {
  seq += 1
  return `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`
}

const NOW = Date.parse('2026-11-17T08:00:00Z')
const iso = (minutesAgo: number) => new Date(NOW - minutesAgo * 60_000).toISOString()

type Run = Record<string, unknown>

function run(over: Run): Run {
  return {
    id: id(),
    tenant_id: '00000000-0000-4000-8000-0000000000aa',
    scan_workflow_id: '00000000-0000-4000-8000-0000000000bb',
    kind: 'scan',
    scan_id: '00000000-0000-4000-8000-0000000000cc',
    scan_name: 'Weekly web scan',
    trigger_type: 'manual',
    trigger: { type: 'user', id: '00000000-0000-4000-8000-0000000000dd', label: 'Ana Example' },
    status: 'completed',
    started_at: iso(30),
    completed_at: iso(10),
    created_at: iso(31),
    total_steps: 2,
    completed_steps: 2,
    failed_steps: 0,
    skipped_steps: 0,
    total_findings: 3,
    ...over,
  }
}

const tasks = (total: number, done: number, failed = 0, running = 0, queued = 0, canceled = 0) => ({
  total,
  completed: done,
  failed,
  running,
  queued,
  canceled,
  sensors: total > 0 ? 1 : 0,
})

/**
 * One run per status first (the card each status renders), then the shapes
 * real data has: long names, messages with and without spaces, no tasks,
 * every task failed, live runs, system-started runs, retests, deleted scans.
 */
export function scanRunFixtures(): Run[] {
  seq = 0
  return [
    // The owner's report: a partial run with a message and failed tasks first.
    run({
      status: 'partial',
      scan_name: LONG_NAME,
      intensity: 'active',
      error_message: PARTIAL_MESSAGE,
      task_summary: tasks(6, 4, 2),
      total_steps: 6,
      completed_steps: 4,
      failed_steps: 2,
    }),
    run({
      status: 'pending',
      started_at: undefined,
      completed_at: undefined,
      total_steps: 0,
      completed_steps: 0,
    }),
    run({
      status: 'running',
      completed_at: undefined,
      intensity: 'intrusive',
      task_summary: tasks(12, 3, 0, 4, 5),
    }),
    run({ status: 'completed', intensity: 'passive', task_summary: tasks(4, 4) }),
    run({
      status: 'failed',
      error_message: FAILED_MESSAGE,
      intensity: 'active',
      task_summary: tasks(6, 0, 6),
      total_findings: 0,
    }),
    run({
      status: 'timeout',
      error_message: 'Run timed out after 4h',
      task_summary: tasks(3, 1, 0, 0, 0, 2),
    }),
    run({
      status: 'canceled',
      error_message: 'Canceled by Ana Example',
      task_summary: tasks(5, 2, 0, 0, 0, 3),
    }),
    run({
      status: 'blocked',
      started_at: undefined,
      completed_at: undefined,
      refusal_code: 'ALL_TARGETS_EXCLUDED',
      error_message: 'Every target of this scan is excluded by the scope rules',
      total_steps: 0,
      completed_steps: 0,
      total_findings: 0,
    }),
    // Shapes.
    run({
      status: 'failed',
      scan_name: LONG_NAME,
      error_message: UNBROKEN_MESSAGE,
      unreachable_target_count: 9,
      skipped_target_count: 373,
      task_summary: tasks(6, 0, 6),
    }),
    run({
      status: 'partial',
      unreachable_target_count: 9,
      skipped_target_count: 373,
      no_longer_resolve_count: 12,
      intensity: 'intrusive',
    }),
    run({
      status: 'completed',
      trigger_type: 'system',
      trigger: { type: 'policy', id: 'coverage' },
      managed_by: 'coverage',
      scan_name: 'Coverage: discovered hosts',
      task_summary: tasks(0, 0),
    }),
    run({
      status: 'running',
      trigger_type: 'schedule',
      trigger: { type: 'schedule' },
      completed_at: undefined,
      task_summary: tasks(6, 0, 0, 0, 6),
    }),
    run({
      status: 'completed',
      kind: 'retest',
      scan_id: undefined,
      scan_name: undefined,
      subject: { finding_id: '00000000-0000-4000-8000-0000000000ee' },
    }),
    run({ status: 'completed', scan_name: '' }),
    run({
      status: 'completed',
      scan_id: undefined,
      scan_name: undefined,
      trigger: undefined,
      triggered_by: undefined,
    }),
  ]
}

/** The list response the runs page reads (GET /api/v1/scan-runs). */
export function scanRunPage(rows: Run[] = scanRunFixtures()) {
  return { data: rows, total: rows.length, page: 1, per_page: 25, total_pages: 1 }
}
