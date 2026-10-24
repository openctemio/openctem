import { cn } from '@/lib/utils'
import type { HealthState } from '@/lib/health-colors'

/**
 * One 12px glyph per machine state, all from the filled-circle family so a
 * column of them reads as one set: check (ok), static half circle (running),
 * dashed ring (queued), "!" (degraded), "x" (down), pause ring, dash ring
 * (off) and "?" ring (unknown). Static shapes: nothing spins or pulses.
 * Decorative: the text beside them carries the meaning.
 */
const ink = 'var(--card)'

export function HealthGlyph({ state, className }: { state: HealthState; className?: string }) {
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 12 12"
      fill="none"
      className={cn('size-3 shrink-0', className)}
    >
      {state === 'ok' && (
        <>
          <circle cx="6" cy="6" r="5.3" fill="currentColor" />
          <path
            d="M3.7 6.2l1.7 1.7 3-3.4"
            stroke={ink}
            strokeWidth="1.4"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </>
      )}
      {state === 'run' && (
        <>
          <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
          <path d="M6 3a3 3 0 0 1 0 6z" fill="currentColor" />
        </>
      )}
      {state === 'queued' && (
        <circle
          cx="6"
          cy="6"
          r="4.5"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeDasharray="2 2"
        />
      )}
      {state === 'warn' && (
        <>
          <circle cx="6" cy="6" r="5.3" fill="currentColor" />
          <path d="M6 3.2v3.3" stroke={ink} strokeWidth="1.4" strokeLinecap="round" />
          <circle cx="6" cy="8.5" r="0.8" fill={ink} />
        </>
      )}
      {state === 'down' && (
        <>
          <circle cx="6" cy="6" r="5.3" fill="currentColor" />
          <path
            d="M4.2 4.2l3.6 3.6M7.8 4.2L4.2 7.8"
            stroke={ink}
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </>
      )}
      {state === 'paused' && (
        <>
          <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
          <path d="M4.9 4.3v3.4M7.1 4.3v3.4" stroke="currentColor" strokeWidth="1.2" />
        </>
      )}
      {state === 'off' && (
        <>
          <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
          <path d="M4 6h4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        </>
      )}
      {state === 'unknown' && (
        <>
          <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
          <path
            d="M4.9 4.9a1.2 1.2 0 1 1 1.7 1.1c-.4.2-.6.5-.6.9"
            stroke="currentColor"
            strokeWidth="1.1"
            strokeLinecap="round"
          />
          <circle cx="6" cy="8.5" r="0.7" fill="currentColor" />
        </>
      )}
    </svg>
  )
}
