/**
 * Scope Feature - Barrel Export
 *
 * Scope entries, exclusions and settings (RFC-054). Whether a target may be
 * probed is answered by the server (POST /scope/check, `useScopeCheck`);
 * nothing here matches patterns in the browser.
 */

// Types
export * from './types'

// API Types and Hooks
export * from './api'

// Codes, entry helpers
export * from './lib/scope-codes'
export * from './lib/scope-entry'

// Components
export * from './components/scope-target-type'
export { ScopeEntryDialog, type ScopeEntryDraft } from './components/scope-entry-dialog'
export {
  ScopeCheckList,
  ScopeCheckRow,
  ScopeFixButtons,
  ScopeRefusalPanel,
  scopeRefusalSummary,
  refusedFromError,
  viaText,
  type ScopeRefusal,
} from './components/scope-check-results'
export { ScopeCheckBadge } from './components/scope-check-badge'
