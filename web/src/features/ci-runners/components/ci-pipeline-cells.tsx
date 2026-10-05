'use client'

import { Badge } from '@/components/ui/badge'
import { TonePill } from '@/features/shared/components/tone-pill'
import { cn } from '@/lib/utils'

import { GATE_LABEL, MODE_LABEL, pipelineStatusMeta } from '../lib/pipeline'
import type { FleetMode } from '../types'

/** A CI pipeline's status as a pill (the API's combined badge). Never "offline". */
export function PipelineStatusBadge({
  status,
  detail,
  className,
}: {
  status?: string
  detail?: React.ReactNode
  className?: string
}) {
  const meta = pipelineStatusMeta(status)
  return (
    <TonePill
      tone={meta.tone}
      label={meta.label}
      title={meta.description}
      state={status}
      detail={detail}
      className={className}
    />
  )
}

/** The default-branch gate in words, coloured only when it fails. */
export function GateLabel({ gate, className }: { gate?: string; className?: string }) {
  return (
    <span
      className={cn(
        'text-sm',
        gate === 'failing'
          ? 'font-medium text-destructive'
          : gate === 'passing'
            ? 'text-foreground'
            : 'text-muted-foreground',
        className
      )}
    >
      {GATE_LABEL[gate ?? 'none'] ?? gate}
    </span>
  )
}

/**
 * The fleet mode of a row: "Daemon" for a sensor row, "Runner · CI pipeline"
 * for a CI pipeline. The legacy v1 sensor type `runner` is not the mode.
 */
export function FleetModeBadge({ mode, className }: { mode?: string; className?: string }) {
  const m: FleetMode = mode === 'runner' ? 'runner' : 'daemon'
  return (
    <Badge variant="outline" className={cn('whitespace-nowrap font-normal', className)}>
      {MODE_LABEL[m]}
      {m === 'runner' && <span className="text-muted-foreground">· CI pipeline</span>}
    </Badge>
  )
}
