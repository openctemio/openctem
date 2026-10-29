/**
 * Dashboard widget kit: one frame with every state, and visualizations over
 * the widget result shapes. See api/docs/architecture/dashboards.md
 * ("Widget kit").
 */
export * from './types'
export {
  changeOf,
  deltaTone,
  isStale,
  stageStateOf,
  stateFromError,
  targetStatus,
  type DeltaTone,
  type TargetStatus,
} from './compare'
export { WidgetFrame, WidgetErrorBoundary, type WidgetFrameProps } from './widget-frame'
export { StatViz, ProgressViz, type StatVizProps } from './stat-viz'
export { BarViz, barRows, type BarVizProps } from './bar-viz'
export { ColumnViz, AreaLineViz, DivergingViz, netOf, toRows } from './series-viz'
export { HeatmapViz, ItemsViz, heatStep } from './grid-viz'
export { LoopViz } from './loop-viz'
export { PathsViz } from './paths-viz'
export { ExposureFlowViz } from './exposure-flow-viz'
export { IntakeViz, SourceTable } from './intake-viz'
export { CategoryTable, TimeSeriesTable, MatrixTable, StagesTable, PathsTable } from './table-viz'
export {
  ChartOrTable,
  DeltaText,
  DrillLink,
  Legend,
  Sparkline,
  TargetChip,
  foldOther,
  usePrefersReducedMotion,
  type LegendEntry,
} from './viz-parts'
