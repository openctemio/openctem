/**
 * Markdown formatting commands for a plain <textarea>.
 *
 * Each command takes the current text and selection and returns one edit:
 * the range to replace, the replacement, and the selection to restore. The
 * editor applies the edit with the browser's insertText so native undo/redo
 * keeps working. Pure functions, so they are unit tested on their own.
 */

export type MarkdownCommandId =
  | 'bold'
  | 'italic'
  | 'strike'
  | 'code'
  | 'link'
  | 'quote'
  | 'heading'
  | 'bulletList'
  | 'numberedList'
  | 'checklist'
  | 'codeBlock'
  | 'table'
  | 'hr'
  | 'image'

export interface TextSelection {
  value: string
  start: number
  end: number
}

export interface MarkdownEdit {
  /** Range of `value` that `text` replaces. */
  from: number
  to: number
  text: string
  /** Selection after the edit, in the new text. */
  selStart: number
  selEnd: number
}

const WRAP: Partial<Record<MarkdownCommandId, string>> = {
  bold: '**',
  italic: '_',
  strike: '~~',
  code: '`',
}

const PREFIX: Partial<Record<MarkdownCommandId, string>> = {
  quote: '> ',
  heading: '### ',
  bulletList: '- ',
  checklist: '- [ ] ',
}

/** Placeholder words a command inserts when nothing is selected. */
export interface MarkdownPlaceholders {
  text: string
  url: string
  code: string
  column: string
}

const DEFAULT_PLACEHOLDERS: MarkdownPlaceholders = {
  text: 'text',
  url: 'https://',
  code: 'code',
  column: 'Column',
}

function wrap(sel: TextSelection, marker: string, placeholder: string): MarkdownEdit {
  const { value, start, end } = sel
  const selected = value.slice(start, end)
  const m = marker.length
  // Toggle off when the selection is already wrapped in the marker.
  if (
    start >= m &&
    value.slice(start - m, start) === marker &&
    value.slice(end, end + m) === marker
  ) {
    return {
      from: start - m,
      to: end + m,
      text: selected,
      selStart: start - m,
      selEnd: end - m,
    }
  }
  const inner = selected || placeholder
  return {
    from: start,
    to: end,
    text: `${marker}${inner}${marker}`,
    selStart: start + m,
    selEnd: start + m + inner.length,
  }
}

/** Start of the line that holds `pos`. */
function lineStart(value: string, pos: number): number {
  return value.lastIndexOf('\n', pos - 1) + 1
}

/** End of the line that holds `pos` (index of its newline, or the text end). */
function lineEnd(value: string, pos: number): number {
  const i = value.indexOf('\n', pos)
  return i === -1 ? value.length : i
}

function prefixLines(sel: TextSelection, prefixFor: (i: number) => string): MarkdownEdit {
  const { value, start, end } = sel
  const from = lineStart(value, start)
  // A selection that ends right after a newline does not include that line.
  const to = lineEnd(value, end > start && value[end - 1] === '\n' ? end - 1 : end)
  const lines = value.slice(from, to).split('\n')
  const first = prefixFor(0)
  // Toggle off when every line already has the prefix.
  const allPrefixed = lines.every((l, i) => l.startsWith(prefixFor(i)))
  const next = allPrefixed
    ? lines.map((l, i) => l.slice(prefixFor(i).length))
    : lines.map((l, i) => prefixFor(i) + l)
  const text = next.join('\n')
  if (start === end) {
    const shift = allPrefixed ? -first.length : first.length
    const caret = Math.max(from, start + shift)
    return { from, to, text, selStart: caret, selEnd: caret }
  }
  return { from, to, text, selStart: from, selEnd: from + text.length }
}

/** Newlines needed before a block so it starts on its own paragraph. */
function blockLead(value: string, pos: number): string {
  if (pos === 0) return ''
  if (value.slice(pos - 2, pos) === '\n\n') return ''
  return value[pos - 1] === '\n' ? '\n' : '\n\n'
}

function insertBlock(sel: TextSelection, block: string, caretOffset: number, selLen = 0) {
  const lead = blockLead(sel.value, sel.start)
  const text = `${lead}${block}`
  const caret = sel.start + lead.length + caretOffset
  return { from: sel.start, to: sel.end, text, selStart: caret, selEnd: caret + selLen }
}

export function applyMarkdownCommand(
  id: MarkdownCommandId,
  sel: TextSelection,
  placeholders: Partial<MarkdownPlaceholders> = {}
): MarkdownEdit {
  const ph = { ...DEFAULT_PLACEHOLDERS, ...placeholders }
  const marker = WRAP[id]
  if (marker) return wrap(sel, marker, id === 'code' ? ph.code : ph.text)
  const prefix = PREFIX[id]
  if (prefix) return prefixLines(sel, () => prefix)

  const selected = sel.value.slice(sel.start, sel.end)
  switch (id) {
    case 'numberedList':
      return prefixLines(sel, (i) => `${i + 1}. `)
    case 'link':
    case 'image': {
      const bang = id === 'image' ? '!' : ''
      const label = selected || ph.text
      const text = `${bang}[${label}](${ph.url})`
      // Select the URL so the author types over it.
      const urlStart = sel.start + bang.length + label.length + 3
      return {
        from: sel.start,
        to: sel.end,
        text,
        selStart: urlStart,
        selEnd: urlStart + ph.url.length,
      }
    }
    case 'codeBlock': {
      const body = selected || ph.code
      const block = `\`\`\`\n${body}\n\`\`\`\n`
      // Caret right after the opening fence, where the language goes.
      return insertBlock(sel, block, 3)
    }
    case 'table': {
      const c = ph.column
      const block = `| ${c} 1 | ${c} 2 |\n| --- | --- |\n|  |  |\n`
      return insertBlock(sel, block, 2, `${c} 1`.length)
    }
    case 'hr':
      return insertBlock(sel, '---\n', 4)
    default:
      return { from: sel.start, to: sel.end, text: selected, selStart: sel.start, selEnd: sel.end }
  }
}

/** Applies an edit to a string (for tests and for the non-DOM fallback). */
export function applyEdit(value: string, edit: MarkdownEdit): string {
  return value.slice(0, edit.from) + edit.text + value.slice(edit.to)
}
