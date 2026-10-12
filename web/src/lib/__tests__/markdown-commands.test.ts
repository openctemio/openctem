import { describe, expect, it } from 'vitest'
import { applyEdit, applyMarkdownCommand } from '../markdown-commands'

const run = (
  id: Parameters<typeof applyMarkdownCommand>[0],
  value: string,
  start: number,
  end = start
) => {
  const edit = applyMarkdownCommand(id, { value, start, end })
  const next = applyEdit(value, edit)
  return { next, sel: next.slice(edit.selStart, edit.selEnd), edit }
}

describe('applyMarkdownCommand', () => {
  it('wraps the selection and keeps it selected', () => {
    const r = run('bold', 'say hello now', 4, 9)
    expect(r.next).toBe('say **hello** now')
    expect(r.sel).toBe('hello')
  })

  it('unwraps a selection that is already wrapped', () => {
    const r = run('bold', 'say **hello** now', 6, 11)
    expect(r.next).toBe('say hello now')
    expect(r.sel).toBe('hello')
  })

  it('inserts a placeholder when nothing is selected', () => {
    const r = run('italic', 'ab', 1)
    expect(r.next).toBe('a_text_b')
    expect(r.sel).toBe('text')
  })

  it('prefixes every selected line and toggles back', () => {
    const r = run('bulletList', 'one\ntwo\nthree', 0, 7)
    expect(r.next).toBe('- one\n- two\nthree')
    const back = run('bulletList', r.next, 0, 11)
    expect(back.next).toBe('one\ntwo\nthree')
  })

  it('numbers lines in order', () => {
    expect(run('numberedList', 'a\nb', 0, 3).next).toBe('1. a\n2. b')
  })

  it('selects the URL of a new link', () => {
    const r = run('link', 'see docs', 4, 8)
    expect(r.next).toBe('see [docs](https://)')
    expect(r.sel).toBe('https://')
  })

  it('puts a code block on its own paragraph with the caret at the language', () => {
    const r = run('codeBlock', 'intro', 5)
    expect(r.next).toBe('intro\n\n```\ncode\n```\n')
    expect(r.edit.selStart).toBe('intro\n\n```'.length)
  })

  it('inserts a table and selects its first header', () => {
    const r = run('table', '', 0)
    expect(r.next.startsWith('| Column 1 | Column 2 |\n| --- | --- |')).toBe(true)
    expect(r.sel).toBe('Column 1')
  })
})
