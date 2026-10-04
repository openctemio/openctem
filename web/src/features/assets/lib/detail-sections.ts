import type { ReactNode } from 'react'
import type { Asset } from '../types'
import type { DetailFieldConfig, DetailSectionConfig } from '../types/page-config.types'

export interface ResolvedDetailField {
  label: string
  value: ReactNode
  fullWidth?: boolean
}

export interface ResolvedDetailSection {
  title: string
  fields: ResolvedDetailField[]
}

export interface ResolvedDetailSections {
  /** Sections with at least one field to show, fields with a value only. */
  sections: ResolvedDetailSection[]
  /** The facts no scan collected, once each, in field order. */
  notCollected: string[]
}

function missingLabel(field: DetailFieldConfig, value: ReactNode, asset: Asset): string | null {
  const nc = field.notCollected
  if (!nc) return null
  if (typeof nc === 'function') return nc(asset) || null
  return value === null || value === undefined ? nc : null
}

/**
 * Resolve a typed page's detail sections for one asset (asset-page.tsx).
 * Fields whose value is null / undefined are dropped and a section left
 * with none is dropped; the facts those fields name in `notCollected` are
 * gathered for the single "Not collected yet: …" line.
 */
export function resolveDetailSections(
  sections: readonly DetailSectionConfig[],
  asset: Asset
): ResolvedDetailSections {
  const notCollected: string[] = []
  const resolved: ResolvedDetailSection[] = []
  for (const section of sections) {
    const fields: ResolvedDetailField[] = []
    for (const field of section.fields) {
      const value = field.getValue(asset)
      const missing = missingLabel(field, value, asset)
      if (missing && !notCollected.includes(missing)) notCollected.push(missing)
      if (value !== null && value !== undefined)
        fields.push({ label: field.label, value, fullWidth: field.fullWidth })
    }
    if (fields.length > 0) resolved.push({ title: section.title, fields })
  }
  return { sections: resolved, notCollected }
}
