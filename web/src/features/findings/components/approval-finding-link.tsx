'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'

/**
 * The finding an approval request is about, by title, linking to it. An
 * approval list row used to show the first characters of the finding id.
 * The title is scanner or member input: plain text, capped, bidi-isolated.
 */
export function ApprovalFindingLink({
  findingId,
  findingTitle,
}: {
  findingId: string
  findingTitle?: string
}) {
  const { t } = useTranslation()
  const title = toDisplayText(findingTitle ?? '', 500).trim()
  return (
    <Link
      href={`/findings/${encodeURIComponent(findingId)}`}
      dir="auto"
      className="text-primary line-clamp-2 max-w-[320px] text-sm [unicode-bidi:isolate] hover:underline"
      title={title || undefined}
    >
      {title || t('findings.approvalLink.untitled', 'Untitled finding')}
    </Link>
  )
}
