/**
 * The "open a form" link the Create menu, its "c" chords and the command
 * palette use: `?new=<form>` on a page
 * opens that page's create form once, and the param is then removed from the
 * address so a reload or Back does not open it again. The page still checks
 * its own permission before it opens anything; the param only says which
 * form to show.
 */

export type OpenForm = 'scan' | 'import' | 'asset' | 'finding' | 'task' | 'invite'

const FORMS: ReadonlySet<string> = new Set<OpenForm>([
  'scan',
  'import',
  'asset',
  'finding',
  'task',
  'invite',
])

/** The page address that opens a form. */
export function openFormHref(path: string, form: OpenForm): string {
  return `${path}?new=${form}`
}

/** The form a search string asks for, or null. */
export function requestedForm(search: string | URLSearchParams): OpenForm | null {
  const q = typeof search === 'string' ? new URLSearchParams(search) : search
  const v = q.get('new')
  return v && FORMS.has(v) ? (v as OpenForm) : null
}
