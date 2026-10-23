import { cn } from '@/lib/utils'
import type { SeverityLevel } from '@/lib/severity'
import { SEVERITY_MARK_COLORS } from '@/lib/severity-colors'

/**
 * One distinct 12px shape per severity, so the scale reads without colour:
 * critical an octagon with "!", high a triangle, medium a diamond, low a
 * filled circle, info a ring. Decorative: the text label always accompanies it.
 */
export function SeverityGlyph({
  level,
  className,
}: {
  level: SeverityLevel | null | undefined
  className?: string
}) {
  const color = level ? SEVERITY_MARK_COLORS[level] : 'text-muted-foreground'
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 12 12"
      className={cn('size-3 shrink-0', color, className)}
      fill="currentColor"
    >
      {level === 'critical' && (
        <path
          fillRule="evenodd"
          d="M4 .8h4L11.2 4v4L8 11.2H4L.8 8V4zM5.35 3h1.3v3.7h-1.3zM6 7.7a.85.85 0 1 0 0 1.7.85.85 0 0 0 0-1.7z"
        />
      )}
      {level === 'high' && <path d="M6 1 11.2 10.5H.8z" />}
      {level === 'medium' && <path d="M6 .6 11.4 6 6 11.4.6 6z" />}
      {level === 'low' && <circle cx="6" cy="6" r="4.5" />}
      {level === 'info' && (
        <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="1.5" />
      )}
      {level === null && (
        <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="1.5" />
      )}
    </svg>
  )
}
