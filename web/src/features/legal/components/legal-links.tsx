import { Fragment, type ReactNode } from 'react'

import { TEXT_LINK_CLASS } from '@/components/ui/text-link'
import { safeHref } from '@/lib/safe-href'

/**
 * An e-mail address in the legal text: a `mailto:` link (the address comes
 * from the legal settings, so it still goes through the safe-href check;
 * anything that does not pass stays plain text).
 */
export function LegalMail({ to }: { to: string }) {
  const mailHref = safeHref(`mailto:${to}`, { allowRelative: false, allowMailto: true })
  if (!mailHref) return <>{to}</>
  return (
    <a href={mailHref} className={TEXT_LINK_CLASS.inline}>
      {to}
    </a>
  )
}

/** A web address in the legal text (website, documentation): an http(s) link, or plain text. */
export function LegalWeb({ url }: { url: string }) {
  const webHref = safeHref(url, { allowRelative: false })
  if (!webHref) return <>{url}</>
  return (
    <a href={webHref} rel="noopener noreferrer" className={TEXT_LINK_CLASS.inline}>
      {url}
    </a>
  )
}

/**
 * A translated line with `{name}` marks, the marks replaced by nodes (links).
 * The translation is asked with each mark as its own value, so the words
 * around it stay in the translator's order.
 */
export function withNodes(line: string, nodes: Record<string, ReactNode>): ReactNode {
  const names = Object.keys(nodes)
  if (names.length === 0) return line
  const re = new RegExp(`(${names.map((n) => `\\{${n}\\}`).join('|')})`)
  return line.split(re).map((part, i) => {
    const m = /^\{(.+)\}$/.exec(part)
    if (m && m[1] in nodes) return <Fragment key={i}>{nodes[m[1]]}</Fragment>
    return <Fragment key={i}>{part}</Fragment>
  })
}
