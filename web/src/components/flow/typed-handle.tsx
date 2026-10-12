'use client'

import { Handle, Position } from '@xyflow/react'
import { cn } from '@/lib/utils'

/**
 * A connection handle that names the port types it carries (title and
 * accessible name). Colour is a helper only: PortChips writes the types out,
 * so the meaning never depends on colour.
 */
export function TypedHandle({
  type,
  ports,
  label,
}: {
  type: 'source' | 'target'
  ports: string[]
  /** Accessible name prefix, e.g. "Takes" / "Gives". */
  label: string
}) {
  const isTarget = type === 'target'
  const text = ports.length > 0 ? ports.join(', ') : 'no typed data'
  return (
    <Handle
      type={type}
      position={isTarget ? Position.Left : Position.Right}
      aria-label={`${label}: ${text}`}
      title={`${label}: ${text}`}
      data-ports={ports.join(',')}
      className={cn(
        '!h-3 !w-3 !border-2 !border-background',
        ports.length === 0 ? '!bg-muted-foreground' : isTarget ? '!bg-info' : '!bg-primary',
        isTarget ? '!-left-1.5' : '!-right-1.5'
      )}
    />
  )
}

/** The port types of a node, written out ("takes hostname, ip"). */
export function PortChips({
  label,
  ports,
  labels,
}: {
  label: string
  ports: string[]
  labels?: Record<string, string>
}) {
  if (ports.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span className="text-[10px] text-muted-foreground">{label}</span>
      {ports.map((p) => (
        <span
          key={p}
          title={labels?.[p] ?? p}
          className="rounded border bg-muted px-1 font-mono text-[9px] leading-4 text-muted-foreground"
        >
          {p}
        </span>
      ))}
    </div>
  )
}
