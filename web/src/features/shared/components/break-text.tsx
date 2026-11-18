import * as React from 'react'

/**
 * Names and addresses (host names, e-mail addresses, URLs, file and package
 * names) wrap only at their separators, never inside a word: "payments-api.
 * example.com" may wrap after a dot or a dash, "Payments platform" never
 * becomes "Paym|ents".
 *
 * The browser has no break opportunity inside such a token, so a long one
 * either runs out of its box or, with the break-at-any-letter utilities,
 * breaks inside a word. This inserts an invisible `<wbr>` after each
 * separator (before an `@`, so the domain starts the next line); the text,
 * its copy and its accessible name stay exactly the same.
 *
 * Use it with `break-words` (a token with no separator that is still wider
 * than its box breaks there as a last resort, instead of overflowing).
 */
const SEPARATORS = /([./\-_@:?&=#])/

export function breakAtSeparators(text: string): React.ReactNode {
  if (!text || !SEPARATORS.test(text)) return text
  const parts = text.split(SEPARATORS)
  const out: React.ReactNode[] = []
  parts.forEach((part, i) => {
    if (!part) return
    if (part === '@') {
      out.push(<wbr key={`w${i}`} />, part)
    } else if (part.length === 1 && SEPARATORS.test(part)) {
      out.push(part, <wbr key={`w${i}`} />)
    } else {
      out.push(part)
    }
  })
  return out
}

/**
 * A name or address that wraps only at its separators (see
 * `breakAtSeparators`). Anything that is not a string is rendered as given.
 */
export function BreakText({ children }: { children: React.ReactNode }) {
  return <>{typeof children === 'string' ? breakAtSeparators(children) : children}</>
}
