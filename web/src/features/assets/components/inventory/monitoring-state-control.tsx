'use client'

/**
 * The inline monitoring control of an inventory row: the row's monitoring
 * state as a menu that records an ownership decision (PUT
 * /assets/{id}/attribution, the typed and audited command; confirming may ask
 * for re-authentication and adds the asset's exact scope entry). Each choice
 * says what it does. Without assets:write (canWrite) it is the plain state chip.
 */

import { useState } from 'react'
import { ChevronDown, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'
import { useDecideAttribution } from '../../hooks/use-asset-attribution'
import type { AttributionDecision } from '../../lib/attribution'
import { decisionHint, decisionLabel } from '../asset-attribution-section'
import { MonitoringStateChip } from './monitoring-state-chip'
import { MONITORING_STATE_FALLBACK, isMonitoringState } from '../../lib/monitoring-state'

/** The decisions offered for a row: every decision but the one in force. */
export function monitoringDecisions(attributionState: string | undefined): AttributionDecision[] {
  const all: AttributionDecision[] = ['confirmed', 'monitor_only', 'dependency', 'rejected']
  const offered = all.filter((d) => d !== attributionState)
  // A decided asset can hand the decision back to a person's review.
  if (attributionState && attributionState !== 'needs_review') offered.push('needs_review')
  return offered
}

export function MonitoringStateControl({
  assetId,
  assetName,
  state,
  attributionState,
  canWrite,
  onChanged,
}: {
  assetId: string
  assetName: string
  state: string | undefined
  attributionState?: string
  /** The caller holds assets:write (the API checks it again). */
  canWrite: boolean
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const { decide, saving } = useDecideAttribution(assetId)
  const [open, setOpen] = useState(false)
  // The visible chip text leads the accessible name (label in name).
  const stateLabel = isMonitoringState(state)
    ? t(`assets.monitoring.state.${state}`, MONITORING_STATE_FALLBACK[state])
    : ''
  if (!canWrite || !state) return <MonitoringStateChip state={state} />

  const onPick = async (d: AttributionDecision) => {
    try {
      await decide(d)
      toast.success(
        t('assets.monitoring.control.saved', 'Saved the decision for {name}', { name: assetName })
      )
      onChanged?.()
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('assets.attribution.toast.failed', 'Could not save the decision')
      )
    }
  }

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-auto gap-1 px-1 py-0.5"
          disabled={saving}
          aria-label={t('assets.monitoring.control.open', '{state}, change monitoring of {name}', {
            state: stateLabel,
            name: assetName,
          })}
          onClick={(e) => e.stopPropagation()}
        >
          <MonitoringStateChip state={state} />
          {saving ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        className="w-80 max-w-[calc(100vw-2rem)]"
        onClick={(e) => e.stopPropagation()}
      >
        <DropdownMenuLabel>
          {t('assets.monitoring.control.title', 'Decide monitoring')}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {monitoringDecisions(attributionState).map((d) => (
          <DropdownMenuItem
            key={d}
            className="flex flex-col items-start gap-0.5"
            onSelect={() => void onPick(d)}
          >
            <span className="font-medium">{decisionLabel(t, d)}</span>
            <span className="text-xs text-muted-foreground">{decisionHint(t, d)}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
