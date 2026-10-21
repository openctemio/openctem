/**
 * Issue type per kind of issue on a ticketing integration
 * (config.ticketing.issue_types; api/docs/architecture/ticketing-integration.md,
 * "Issue types").
 */

export const ISSUE_KINDS = ['finding', 'task', 'epic'] as const
export type IssueKind = (typeof ISSUE_KINDS)[number]

/** The type a kind uses when nothing is chosen (the API's stock types). */
export const STOCK_ISSUE_TYPES: Record<IssueKind, string> = {
  finding: 'Bug',
  task: 'Task',
  epic: 'Epic',
}

export interface IssueTypeChoice {
  id: string
  name: string
}

export type IssueTypeChoices = Partial<Record<IssueKind, IssueTypeChoice>>

/** metadata.ticketing_health: the last create refusal per kind. */
export type TicketingHealth = Partial<
  Record<IssueKind, { issue_type?: string; fields?: string[]; at?: string }>
>

const ISSUE_TYPE_ID = /^\d{1,20}$/

/** Reads config.ticketing.issue_types, keeping well-formed entries only. */
export function readIssueTypes(ticketing: Record<string, unknown> | undefined): IssueTypeChoices {
  const raw = ticketing?.issue_types
  const out: IssueTypeChoices = {}
  if (!raw || typeof raw !== 'object') return out
  for (const kind of ISSUE_KINDS) {
    const e = (raw as Record<string, unknown>)[kind]
    if (!e || typeof e !== 'object') continue
    const id = typeof (e as { id?: unknown }).id === 'string' ? (e as { id: string }).id : ''
    const name =
      typeof (e as { name?: unknown }).name === 'string' ? (e as { name: string }).name : ''
    if (!id && !name) continue
    out[kind] = { id: ISSUE_TYPE_ID.test(id) ? id : '', name }
  }
  return out
}

/** Reads metadata.ticketing_health. */
export function readTicketingHealth(
  metadata: Record<string, unknown> | undefined
): TicketingHealth {
  const raw = metadata?.ticketing_health
  if (!raw || typeof raw !== 'object') return {}
  const out: TicketingHealth = {}
  for (const kind of ISSUE_KINDS) {
    const e = (raw as Record<string, unknown>)[kind]
    if (!e || typeof e !== 'object') continue
    const fields = Array.isArray((e as { fields?: unknown }).fields)
      ? ((e as { fields: unknown[] }).fields.filter((f) => typeof f === 'string') as string[])
      : []
    const issueType = (e as { issue_type?: unknown }).issue_type
    out[kind] = { fields, issue_type: typeof issueType === 'string' ? issueType : undefined }
  }
  return out
}

/** The stored shape: only the kinds that have a choice. */
export function issueTypesForSave(choices: IssueTypeChoices): Record<string, IssueTypeChoice> {
  const out: Record<string, IssueTypeChoice> = {}
  for (const kind of ISSUE_KINDS) {
    const c = choices[kind]
    if (c && (c.id || c.name)) out[kind] = { id: c.id, name: c.name }
  }
  return out
}

/** Names that suggest a type for a kind, best first. */
const SUGGESTIONS: Record<IssueKind, RegExp[]> = {
  finding: [/security\s*finding/i, /vulnerab/i, /security/i, /^bug$/i],
  task: [/remediation/i, /security\s*task/i, /^task$/i],
  epic: [/^epic$/i, /initiative/i, /campaign/i],
}

/** The issue type whose name best fits a kind, if any. */
export function suggestIssueType<T extends { id: string; name: string }>(
  kind: IssueKind,
  types: T[]
): T | undefined {
  for (const re of SUGGESTIONS[kind]) {
    const hit = types.find((it) => re.test(it.name))
    if (hit) return hit
  }
  return undefined
}
