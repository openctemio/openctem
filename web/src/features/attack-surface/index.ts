// Hooks
export { useAttackSurfaceStats } from './hooks/use-attack-surface'
export type {
  AttackSurfaceStats,
  AssetTypeBreakdown,
  ExposedService,
  AssetChange,
} from './hooks/use-attack-surface'

export { useAttackPathDetail } from './hooks/use-attack-path-detail'
export type {
  AttackPathDetail,
  AttackPath,
  PathNode,
  PathEdge,
} from './hooks/use-attack-path-detail'

// Components
export { PathGraph, EASMOverview } from './components'
export { useEASMSummary } from './hooks/use-easm-summary'
export { EASMReviewQueue } from './components/easm-review-queue'
export { EASMDecidePanel } from './components/easm-decide-panel'
export { EASMLookalikes } from './components/easm-lookalikes'
export { AssetWebEvidenceCard } from './components/asset-web-evidence-card'
export { EASMChanges } from './components/easm-changes'
export { EASMCertificates } from './components/easm-certificates'
export { EASMExposureItems } from './components/easm-exposure-items'
export { EASMTechnologies } from './components/easm-technologies'
export { AttackSurfaceSectionTabs } from './components/attack-surface-section-tabs'
export { useEASMReviewQueue, useDecideReviewBatch } from './hooks/use-easm-review'
export type { PathGraphNode, PathGraphPath, PathNodeRole } from './components'

export { useExposureChains } from './hooks/use-exposure-chains'
export type {
  ExposureChains,
  ExposureChain,
  ExposureChainSummary,
  ChainHop,
} from './hooks/use-exposure-chains'
