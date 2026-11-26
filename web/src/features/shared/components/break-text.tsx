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
 * An e-mail address breaks only before its `@`: the person's part and the
 * domain each stay whole ("thong.tin" / "@example.com.vn"), never
 * "thong.tin@example.com." / "vn" at a dot or "openctem-" / "test.local" at
 * a hyphen of the domain. Each part is a `data-email-part` span that
 * globals.css keeps in one piece.
 *
 * Use it with `break-words` (a token with no separator that is still wider
 * than its box breaks there as a last resort, instead of overflowing).
 */
const SEPARATORS = /([./\-_@:?&=#])/
/**
 * Where an e-mail address's `@` is (a part, one `@`, a domain with a dot
 * inside it, no space), else -1. No regular expression: linear on any text.
 */
function emailAt(text: string): number {
  const at = text.indexOf('@')
  if (at < 1 || text.indexOf('@', at + 1) !== -1 || /\s/.test(text)) return -1
  const dot = text.indexOf('.', at + 2)
  return dot > 0 && dot < text.length - 1 ? at : -1
}

export function breakAtSeparators(text: string): React.ReactNode {
  if (!text || !SEPARATORS.test(text)) return text
  const at = emailAt(text)
  if (at > 0) {
    return [
      <span key="user" data-email-part="">
        {text.slice(0, at)}
      </span>,
      <wbr key="at" />,
      <span key="domain" data-email-part="">
        {text.slice(at)}
      </span>,
    ]
  }
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
