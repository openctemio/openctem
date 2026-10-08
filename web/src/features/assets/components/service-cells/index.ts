/**
 * Shared cells for asset lists. Every asset list that shows services or web
 * hosts uses these; no page keeps its own copy (sync rule, ui-style-contract).
 *
 * - external-surface facts, per type via `cellsForType`: `SurfaceFacts`,
 *   `HttpStatusChip`, `OverflowChips`, `TechChips`, `TlsSummary`,
 *   `CertExpiryChip`, `PortChip`, `OpenPortChips`, `ProductChip`;
 * - every type: `LabelChips` (tags, "+ Add label") and `IssuesChip`;
 * - building blocks: `FactChip`, `ChipRow`, `ChipMono`;
 * - facts nothing collected (ui-style-contract §7, "Unknown facts"): every
 *   cell renders nothing for them (its `fallback` prop overrides that),
 *   `EmptyCell` is the muted `—` of a list cell left empty, and a drawer
 *   names them once with `NotCollectedNote` (`missingSurfaceFacts`,
 *   `tlsNotCollected`, `SurfaceFactsDetail`).
 *
 * Links built from scanner data use the shared `SafeExternalLink` /
 * `safeHref` (src/components/safe-external-link.tsx, src/lib/safe-href.ts).
 */
export { FactChip, ChipRow, ChipMono, type FactChipTone } from './fact-chip'
export { EmptyCell, NotCollectedNote, notCollectedText } from './not-collected'
export { HttpStatusChip, httpStatusTone, httpReason } from './http-status-chip'
export { IssuesChip, assetFindingsHref } from './issues-chip'
export { OverflowChips } from './overflow-chips'
export { TechChips } from './tech-chips'
export { TlsSummary, CertExpiryChip, tlsNotCollected } from './tls-summary'
export { LabelChips, labelError, MAX_TAGS_PER_ASSET, MAX_TAG_LENGTH } from './label-chips'
export {
  SurfaceFacts,
  SurfaceFactsDetail,
  PortChip,
  OpenPortChips,
  ProductChip,
  missingSurfaceFacts,
  hasSurfaceFacts,
} from './surface-facts'
export {
  cellsForType,
  surfaceCellsCovered,
  SURFACE_CELLS,
  type SurfaceCell,
} from './cells-for-type'
