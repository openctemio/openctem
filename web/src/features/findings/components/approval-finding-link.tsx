import Link from 'next/link'

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
  const title = findingTitle?.trim()
  return (
    <Link
      href={`/findings/${encodeURIComponent(findingId)}`}
      className="text-primary line-clamp-2 max-w-[320px] text-sm hover:underline"
      title={title || undefined}
    >
      {title || 'Untitled finding'}
    </Link>
  )
}
