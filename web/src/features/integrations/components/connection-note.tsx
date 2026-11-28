'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { connectionNote } from '../lib/connection-status'

/**
 * The line under a connection in a list: why it failed, or when a member
 * turned it off, in the reader's language (connectionNote). Renders nothing
 * for a healthy connection.
 */
export function ConnectionNote({
  integration,
  className,
}: {
  integration: Parameters<typeof connectionNote>[0]
  className?: string
}) {
  const { t, locale } = useTranslation()
  const note = connectionNote(integration, t, locale)
  if (!note) return null
  return (
    <span
      data-testid="connection-note"
      title={note.text}
      className={cn(
        'line-clamp-2 block text-xs [overflow-wrap:anywhere]',
        note.tone === 'error' ? 'text-destructive' : 'text-muted-foreground',
        className
      )}
    >
      {note.text}
    </span>
  )
}
