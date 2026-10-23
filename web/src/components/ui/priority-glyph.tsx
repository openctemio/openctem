import { cn } from '@/lib/utils'

/**
 * Three ascending bars; `filled` of them are solid (P0 3, P1 2, P2 1, P3 0).
 * Decorative: the class text beside it carries the meaning.
 */
export function PriorityGlyph({
  filled,
  className,
}: {
  filled: 0 | 1 | 2 | 3
  className?: string
}) {
  const bars = [
    { x: 1, y: 7, h: 4 },
    { x: 5, y: 4, h: 7 },
    { x: 9, y: 1, h: 10 },
  ]
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 12 12"
      className={cn('size-3 shrink-0', className)}
      fill="currentColor"
    >
      {bars.map((b, i) => (
        <rect
          key={b.x}
          x={b.x}
          y={b.y}
          width={2.5}
          height={b.h}
          rx={0.6}
          opacity={i < filled ? 1 : 0.3}
        />
      ))}
    </svg>
  )
}
