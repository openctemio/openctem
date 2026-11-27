'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/**
 * The finding an approval request is about, by title, linking to it. An
 * approval list row used to show the first characters of the finding id.
 * The title is scanner or member input: plain text, capped, bidi-isolated.
 */
export function ApprovalFindingLink({
  findingId,
  findingTitle,
  lines = 2,
}: {
  findingId: string
  findingTitle?: string
  /** 1 in a one-line table row (the column sets the width); 2 elsewhere. */
  lines?: 1 | 2
}) {
  const { t } = useTranslation()
  const title = toDisplayText(findingTitle ?? '', 500).trim()
  return (
    <Link
      href={`/findings/${encodeURIComponent(findingId)}`}
      dir="auto"
      className={cn(
        'text-primary text-sm [unicode-bidi:isolate] hover:underline',
        lines === 1 ? 'block truncate' : 'line-clamp-2 max-w-[320px]'
      )}
      title={title || undefined}
    >
      {title || t('findings.approvalLink.untitled', 'Untitled finding')}
    </Link>
  )
}
