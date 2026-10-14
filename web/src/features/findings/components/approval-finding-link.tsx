'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The finding an approval request is about, by title, linking to it. An
 * approval list row used to show the first characters of the finding id.
 */
export function ApprovalFindingLink({
  findingId,
  findingTitle,
}: {
  findingId: string
  findingTitle?: string
}) {
  const { t } = useTranslation()
  const title = findingTitle?.trim()
  return (
    <Link
      href={`/findings/${encodeURIComponent(findingId)}`}
      className="text-primary line-clamp-2 max-w-[320px] text-sm hover:underline"
      title={title || undefined}
    >
      {title || t('findings.approvalLink.untitled', 'Untitled finding')}
    </Link>
  )
}
