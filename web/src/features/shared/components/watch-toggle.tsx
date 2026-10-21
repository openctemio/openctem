'use client'

/**
 * The bell on a finding or a task: watching it or not. A toggle button with
 * its state in `aria-pressed`; the text says what pressing does.
 */

import { Bell, BellOff, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'

export interface WatchToggleLabels {
  /** The state shown while watching, e.g. "Watching". */
  watching: string
  /** The state shown while not watching, e.g. "Not watching". */
  notWatching: string
  /** The explanation under the button, per state. */
  hintWatching: string
  hintNotWatching: string
}

export interface WatchToggleProps {
  watching: boolean
  busy?: boolean
  labels: WatchToggleLabels
  onChange: (watching: boolean) => void
}

export function WatchToggle({ watching, busy, labels, onChange }: WatchToggleProps) {
  return (
    <div className="space-y-1">
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-8 gap-1.5"
        aria-pressed={watching}
        disabled={busy}
        onClick={() => onChange(!watching)}
      >
        {busy ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
        ) : watching ? (
          <Bell className="h-3.5 w-3.5" aria-hidden />
        ) : (
          <BellOff className="h-3.5 w-3.5" aria-hidden />
        )}
        {watching ? labels.watching : labels.notWatching}
      </Button>
      <p className="text-xs text-muted-foreground">
        {watching ? labels.hintWatching : labels.hintNotWatching}
      </p>
    </div>
  )
}
