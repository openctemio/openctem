'use client'

import { TonePill } from '@/features/shared/components/tone-pill'
import { cn } from '@/lib/utils'

import { GATE_LABEL, isPipelineStatus, pipelineStatusMeta } from '../lib/pipeline'
import { useTranslation } from '@/context/i18n-provider'

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
  const { t } = useTranslation()
  const meta = pipelineStatusMeta(status)
  const known = isPipelineStatus(status)
  return (
    <TonePill
      tone={meta.tone}
      label={known ? t(`scans.ci.status.${status}.label`, meta.label) : meta.label}
      title={
        known ? t(`scans.ci.status.${status}.description`, meta.description) : meta.description
      }
      state={status}
      detail={detail}
      className={className}
    />
  )
}

/** The default-branch gate in words, coloured only when it fails. */
export function GateLabel({ gate, className }: { gate?: string; className?: string }) {
  const { t } = useTranslation()
  const g = gate ?? 'none'
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
      {GATE_LABEL[g] ? t(`scans.ci.gate.${g}`, GATE_LABEL[g]) : gate}
    </span>
  )
}
