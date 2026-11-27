'use client'

import { CveLink } from '@/features/vulnerabilities/components/cve-link'
import { isCveId } from '@/features/vulnerabilities/lib/vuln-page'
import { toDisplayText } from '@/lib/untrusted-text'
import { maskSensitiveText } from '@/lib/mask-sensitive'
import { cn } from '@/lib/utils'

/**
 * The id after a finding's title in a list row: the CVE (a link to its
 * vulnerability page), else the rule that raised it, in mono 12/16. The title
 * gives way first; a long rule id is cut at 45 % of the line with the full
 * value in its tooltip. The rule id is scanner text: masked (a secret or an
 * address a scanner put in it never shows), escaped and shown as React text
 * only.
 */
export function FindingRowId({
  cve,
  ruleId,
  className,
}: {
  cve?: string | null
  ruleId?: string | null
  className?: string
}) {
  const base = cn(
    'max-w-[45%] shrink-0 truncate font-mono text-xs text-muted-foreground',
    className
  )
  const c = (cve ?? '').trim()
  if (isCveId(c)) {
    return (
      <span data-slot="finding-row-id" className={base}>
        <CveLink id={c} stopPropagation />
      </span>
    )
  }
  const raw = (ruleId ?? '').trim() || c
  if (!raw) return null
  const shown = toDisplayText(maskSensitiveText(raw), 200)
  return (
    <span
      data-slot="finding-row-id"
      dir="auto"
      title={shown}
      className={cn(base, '[unicode-bidi:isolate]')}
    >
      {shown}
    </span>
  )
}
