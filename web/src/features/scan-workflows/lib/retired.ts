import type { ScanWorkflow } from '@/lib/api'

/** What a retired workflow or a copy of one tells the user, from the API fields. */
export function retiredInfo(
  w: Pick<ScanWorkflow, 'is_retired' | 'superseded_by' | 'based_on_retired'>
) {
  if (w.is_retired) {
    return { kind: 'retired' as const, source: undefined, replacement: w.superseded_by }
  }
  if (w.based_on_retired) {
    return {
      kind: 'based-on' as const,
      source: w.based_on_retired.name,
      replacement: w.based_on_retired.superseded_by,
    }
  }
  return null
}
