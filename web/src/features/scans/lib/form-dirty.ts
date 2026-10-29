/**
 * Whether a scan form has changes worth asking about before it closes. The
 * names shown on chips (asset and group names, filled in after load) and the
 * coverage expansion (derived from the targets) are display state, not edits.
 */

import type { NewScanFormData } from '../types'

function stable(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stable)
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.keys(v as Record<string, unknown>)
        .sort()
        .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
        .map((k) => [k, stable((v as Record<string, unknown>)[k])])
    )
  }
  return v
}

export function formSignature(form: NewScanFormData): string {
  // The display-only name lists and the expanded preview are not user edits.
  const {
    assetNames: _assetNames,
    assetGroupNames: _assetGroupNames,
    expandedTargets: _expandedTargets,
    ...targets
  } = form.targets
  return JSON.stringify(stable({ ...form, targets }))
}

export function isFormDirty(form: NewScanFormData, initial: NewScanFormData): boolean {
  return formSignature(form) !== formSignature(initial)
}
