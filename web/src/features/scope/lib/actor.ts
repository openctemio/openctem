/**
 * Who did something to a scope entry or exclusion, as the API returns it
 * (RFC-054 §6.1 "People and provenance"): a member by name, a former member,
 * or the platform with a code. Never the raw id or "system:…" string.
 */
export interface ScopeActor {
  kind?: string
  id?: string
  name?: string
  former_member?: boolean
  code?: string
}

const SYSTEM_LABELS: Record<string, string> = {
  upgrade_wildcard_split: 'OpenCTEM upgrade (wildcard rule change)',
  seed_migration: 'OpenCTEM upgrade (was a discovery seed)',
  system: 'OpenCTEM',
}

export function actorLabel(actor: ScopeActor | null | undefined): string {
  if (!actor) return ''
  if (actor.kind === 'system') return SYSTEM_LABELS[actor.code ?? 'system'] ?? SYSTEM_LABELS.system
  if (actor.name) return actor.name
  if (actor.former_member) return 'Former member'
  return 'Member'
}
