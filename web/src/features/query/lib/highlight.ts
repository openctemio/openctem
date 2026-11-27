/**
 * Colours for the query editor: splits a filter into fields, operators,
 * keywords, values and punctuation, in the browser, as typed. It only reads
 * the text (the server stays the authority on what it means) and returns
 * plain tokens that are rendered as React text, never as markup.
 */

import type { TokenType } from '@/lib/code-tokens'

export interface QueryToken {
  /** The kind, in the shared highlighter's vocabulary (its colours). */
  type: TokenType
  value: string
}

const KEYWORDS = new Set(['and', 'or', 'not', 'in', 'where', 'findings', 'assets', 'scans'])
const OPERATOR = /^(>=|<=|!=|=|:|>|<|~)/ // separator-ok: regex alternation, not a text separator
const NAME = /^[A-Za-z_][\w.]*/
// An operator, or (not) in, after a name makes it a field.
const OP_AFTER = /^\s*(>=|<=|!=|=|:|>|<|~)/ // separator-ok: regex alternation, not a text separator
const IN_AFTER = /^\s+(not\s+)?in\b/i
const WORD = /^[^\s"(),=!<>:~]+/

/** The tokens of `text`; joined, their values give back `text` exactly. */
export function queryTokens(text: string): QueryToken[] {
  const out: QueryToken[] = []
  let i = 0
  // After an operator, the next word is a value even if it looks like a name.
  let afterOperator = false
  const push = (type: TokenType, value: string) => {
    const last = out[out.length - 1]
    if (last && last.type === type && type === 'text') last.value += value
    else out.push({ type, value })
  }
  while (i < text.length) {
    const rest = text.slice(i)
    const space = /^\s+/.exec(rest)
    if (space) {
      push('text', space[0])
      i += space[0].length
      continue
    }
    if (rest[0] === '"') {
      let j = 1
      while (j < rest.length && rest[j] !== '"') j += rest[j] === '\\' ? 2 : 1
      const s = rest.slice(0, Math.min(j + 1, rest.length))
      push('string', s)
      i += s.length
      afterOperator = false
      continue
    }
    if ('(),'.includes(rest[0])) {
      push('punctuation', rest[0])
      i++
      continue
    }
    const op = OPERATOR.exec(rest)
    if (op) {
      push('operator', op[0])
      i += op[0].length
      afterOperator = true
      continue
    }
    if (rest[0] === '-' && !afterOperator && NAME.test(rest.slice(1))) {
      // A leading minus negates the condition after it.
      push('operator', '-')
      i++
      continue
    }
    const ident: RegExpExecArray | null = afterOperator ? null : NAME.exec(rest)
    if (ident) {
      const after = rest.slice(ident[0].length)
      if (KEYWORDS.has(ident[0].toLowerCase())) {
        push('keyword', ident[0])
        afterOperator = ident[0].toLowerCase() === 'in'
      } else if (OP_AFTER.test(after) || IN_AFTER.test(after)) {
        push('function', ident[0])
      } else {
        push('type', ident[0])
      }
      i += ident[0].length
      continue
    }
    const word = WORD.exec(rest)
    const value = word ? word[0] : rest[0]
    push('type', value)
    i += value.length
    afterOperator = false
  }
  return out
}
