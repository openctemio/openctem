/**
 * The result shapes a dashboard widget renders, and the states it can be in.
 * Design: research note 203 (§5.2 result shapes, §9 states), described in
 * api/docs/architecture/dashboards.md ("Widget kit").
 *
 * A widget's data is one of these shapes; any visualization valid for the
 * shape can draw it. Null always means "not measured" and is never drawn as 0.
 */

/** One point of a series: an ISO date (bucket start) and its value. */
export interface SeriesPoint {
  t: string
  v: number
}

/** Which direction is better for a figure: fewer open findings, more within SLA. */
export type Polarity = 'down_good' | 'up_good' | 'neutral'

/** A target a figure is compared with. `warn` is the "close" bound (optional). */
export interface MetricTarget {
  op: '<=' | '>=' | '<' | '>' | '='
  value: number
  warn?: number
  /** Where the target comes from: the organization's program targets or this widget. */
  source?: 'tenant' | 'widget'
}

export interface ScalarResult {
  shape: 'scalar'
  value: number | null
  previous?: number | null
  delta?: number | null
  series?: SeriesPoint[]
  target?: MetricTarget | null
  as_of?: string
  n?: number
}

export interface RatioResult {
  shape: 'ratio'
  num: number
  den: number
  /** Null when den = 0: not measured. */
  value_pct: number | null
  previous_pct?: number | null
  series?: SeriesPoint[]
  target?: MetricTarget | null
  as_of?: string
}

export interface DurationResult {
  shape: 'duration'
  /** Hours. Null when fewer than the minimum sample were measured. */
  median: number | null
  p90: number | null
  n: number
  previous_median?: number | null
  target?: MetricTarget | null
  as_of?: string
}

export interface CategoryRow {
  key: string
  /** Message key for the label; the key itself is shown when absent. */
  label_key?: string
  label?: string
  value: number
  previous?: number | null
}

export interface CategoryResult {
  shape: 'category'
  rows: CategoryRow[]
  total: number
  /** True when the keys are ordinal (severity, priority, age band): keep their order. */
  ordinal?: boolean
  as_of?: string
}

export interface TimeSeries {
  key: string
  label_key?: string
  label?: string
  points: SeriesPoint[]
}

export interface SeriesMarker {
  t: string
  label_key?: string
  label?: string
}

export interface TimeSeriesResult {
  shape: 'time_series'
  bucket: 'day' | 'week' | 'month'
  series: TimeSeries[]
  markers?: SeriesMarker[]
  /** A stock (open count) is drawn as area/line; a flow (opened, fixed) as columns. */
  kind?: 'stock' | 'flow'
  as_of?: string
}

export interface MatrixAxisItem {
  key: string
  label_key?: string
  label?: string
}

export interface MatrixResult {
  shape: 'matrix'
  rows: MatrixAxisItem[]
  cols: MatrixAxisItem[]
  /** cells[row][col]; null = not measured. */
  cells: Array<Array<number | null>>
  as_of?: string
}

export interface ItemRow {
  id: string
  title: string
  kind?: string
  priority?: string | null
  severity?: string | null
  asset?: string | null
  due_at?: string | null
  kev?: boolean
  /** EPSS probability, 0 to 1; absent or null draws the empty bar. */
  epss?: number | null
  /** Same-origin path the row opens. */
  href?: string | null
}

export interface ItemsResult {
  shape: 'items'
  rows: ItemRow[]
  /** The list's real total; absent until the server sends one (never rows.length). */
  total?: number | null
  as_of?: string
}

export type StageState = 'good' | 'warn' | 'crit' | 'unmeasured'

export interface Stage {
  key: string
  label_key?: string
  label?: string
  value: number | null
  unit?: 'count' | 'percent' | 'hours'
  state: StageState
  /** Same-origin path the stage opens. */
  drill?: string | null
  /** Why a stage is not measured. */
  reason_key?: string
  /** A second figure under the main one (e.g. "4 breached"), with its list. */
  detail?: { label_key: string; value: number; drill?: string | null }
  /** A short call to action or note ("Designate crown jewels"). */
  flag_key?: string
}

export interface StagesResult {
  shape: 'stages'
  stages: Stage[]
  /** Index of the stage with the largest gap ("act here"); null when none. */
  focus?: number | null
  as_of?: string
}

export interface PathRow {
  id: string
  name: string
  kind?: string | null
  criticality?: string | null
  /** Number of public entry points that reach it. */
  reachable_from: number
  /** The asset is a public entry point itself. */
  entry_point: boolean
  score: number
  /** Same-origin path the row opens. */
  href?: string | null
}

export interface PathsResult {
  shape: 'paths'
  /** Reachable crown jewels, and designated crown jewels, in scope. */
  reachable: number
  designated: number
  rows: PathRow[]
  as_of?: string
}

/** One figure and the same-origin list it counts (null: no list, plain text). */
export interface FlowFigure {
  key?: string
  value: number
  drill?: string | null
}

export type SourceHealth = 'ok' | 'stale' | 'failed'

/** What one source sent in the window, from its receipts, and its health. */
export interface IntakeSourceRow {
  /** Stable key: origin and tool. */
  id: string
  origin: string
  /** The tool as reported (attacker-influenced text: shown through toDisplayText). */
  tool: string
  receipts: number
  received: number
  created: number
  still_detected: number
  reopened: number
  closed: number
  suppressed: number
  not_stored: number
  last_at: string | null
  last_status: string
  health: SourceHealth
  expected_every_seconds: number | null
  drill: string | null
}

/** Received split into parts that sum to it. */
export interface IntakeNoise {
  received: number
  new: number
  merged: number
  suppressed: number
  not_stored: number
}

export interface IntakeData {
  since: string
  /** Length of the window in days. */
  days: number
  sources: IntakeSourceRow[]
  totals: IntakeSourceRow
  noise: IntakeNoise
  failing: number
  stale: number
  drill: string | null
  false_positive: FlowFigure
}

export interface IntakeResult {
  shape: 'intake'
  intake: IntakeData
  as_of?: string
}

/** The exposure flow: sources, received to actionable, classes, stages, outcomes. */
export interface FlowResult {
  shape: 'flow'
  since: string
  /** Length of the window in days. */
  days: number
  /** Null when the read has a data scope (the intake is an organization figure). */
  intake: IntakeData | null
  /** Message key of why the sources are not shown. */
  intake_reason_key?: string
  actionable: FlowFigure
  classes: FlowFigure[]
  open: FlowFigure
  severity: FlowFigure[]
  past_sla: FlowFigure
  in_progress: FlowFigure
  fixed: FlowFigure
  accepted: FlowFigure
  false_positive: FlowFigure
  stages: StagesResult | null
  as_of?: string
}

export type WidgetResult =
  | ScalarResult
  | RatioResult
  | DurationResult
  | CategoryResult
  | TimeSeriesResult
  | MatrixResult
  | ItemsResult
  | StagesResult
  | PathsResult
  | FlowResult
  | IntakeResult

export type ResultShape = WidgetResult['shape']

/** Every state a widget can be in (one frame renders all of them). */
export type WidgetState =
  | 'loading'
  | 'ready'
  | 'stale'
  | 'no_data_yet'
  | 'no_results'
  | 'not_measured'
  | 'no_access'
  | 'module_off'
  | 'error'
  | 'partial'
  | 'scope_changed'

/** The skeleton a loading widget shows, shaped like what will appear. */
export type SkeletonKind = 'stat' | 'chart' | 'list' | 'grid' | 'stages'

/** Builds the list a mark opens; return undefined when the mark has no list. */
export type DrillFn = (selection: {
  series?: string
  key?: string
  t?: string
}) => string | undefined
