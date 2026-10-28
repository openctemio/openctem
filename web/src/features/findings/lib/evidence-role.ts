/** Roles of a finding's evidence item, in the order a reader meets them. */
export const EVIDENCE_ROLES = ['baseline', 'proof', 'verification', 'supporting'] as const

export type EvidenceRole = (typeof EVIDENCE_ROLES)[number]

/** A role from the API; anything unknown reads as supporting. */
export function toEvidenceRole(value: string | undefined): EvidenceRole {
  return (EVIDENCE_ROLES as readonly string[]).includes(value ?? '')
    ? (value as EvidenceRole)
    : 'supporting'
}

/** The ids in display order after moving the item at index one step. */
export function moveId(ids: readonly string[], index: number, direction: 'up' | 'down'): string[] {
  const to = direction === 'up' ? index - 1 : index + 1
  if (index < 0 || index >= ids.length || to < 0 || to >= ids.length) return [...ids]
  const out = [...ids]
  ;[out[index], out[to]] = [out[to], out[index]]
  return out
}
