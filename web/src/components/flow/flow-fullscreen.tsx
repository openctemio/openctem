'use client'

import * as React from 'react'
import { Maximize, Minimize } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * Full screen for a flow canvas: the same view, with the same page state,
 * drawn in a full-viewport dialog (a full-screen sheet on a phone). The page
 * keeps its state above this component and renders its view through
 * `children(full)`, so depth, filters, expansions and the selection carry
 * over; the canvas inside fits the graph again when it opens.
 *
 * - The canvas shows a "Full screen" button (FlowCanvas reads this context);
 * - `f` inside the view toggles it (not while typing in a field);
 * - Escape, the close button or "Exit full screen" leave it, and the focus
 *   goes back to where it was.
 */

interface FlowFullscreenContextValue {
  full: boolean
  toggle: () => void
}

const FlowFullscreenContext = React.createContext<FlowFullscreenContextValue | null>(null)

export function useFlowFullscreen(): FlowFullscreenContextValue | null {
  return React.useContext(FlowFullscreenContext)
}

/** True when a key press is typing (a field, an editable element). */
function isTyping(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null
  if (!el) return false
  const tag = el.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable
}

export interface FlowFullscreenProps {
  /** The dialog title ("Related assets of 203.0.113.10"). */
  title: string
  /** One line under the title (what the view shows). */
  description?: string
  /** The view, inline (`false`) or full screen (`true`). */
  children: (full: boolean) => React.ReactNode
  className?: string
}

export function FlowFullscreen({ title, description, children, className }: FlowFullscreenProps) {
  const { t } = useTranslation()
  const [full, setFull] = React.useState(false)
  const value = React.useMemo<FlowFullscreenContextValue>(
    () => ({ full, toggle: () => setFull((f) => !f) }),
    [full]
  )
  const onKeyDown = React.useCallback((e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key !== 'f' || e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target)) return
    e.preventDefault()
    setFull((f) => !f)
  }, [])

  return (
    <FlowFullscreenContext.Provider value={value}>
      {/* While full screen the view is drawn in the dialog only; the page state above keeps it. */}
      <div className={className} onKeyDown={onKeyDown} data-testid="flow-fullscreen-inline">
        {!full && children(false)}
      </div>
      <Dialog open={full} onOpenChange={setFull}>
        <DialogContent size="screen" data-testid="flow-fullscreen">
          <DialogHeader className="border-b">
            <DialogTitle className="truncate text-base font-semibold">{title}</DialogTitle>
            <DialogDescription
              className={cn('truncate text-xs text-muted-foreground', !description && 'sr-only')}
            >
              {description ??
                t('common.flow.fullScreenHint', 'Press f or Escape to leave full screen.')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody
            className="flex min-h-0 flex-col overflow-hidden p-4 last:pb-4 sm:p-4 sm:last:pb-4"
            onKeyDown={onKeyDown}
          >
            {full && children(true)}
          </DialogBody>
        </DialogContent>
      </Dialog>
    </FlowFullscreenContext.Provider>
  )
}

/** The canvas toolbar button that opens or leaves full screen. */
export function FlowFullscreenButton({ className }: { className?: string }) {
  const { t } = useTranslation()
  const ctx = useFlowFullscreen()
  if (!ctx) return null
  const label = ctx.full
    ? t('common.flow.exitFullScreen', 'Exit full screen')
    : t('common.flow.fullScreen', 'Full screen')
  const Icon = ctx.full ? Minimize : Maximize
  return (
    <Button
      iconOnlyBelow="sm"
      type="button"
      size="sm"
      variant="outline"
      className={cn('h-8 bg-card px-2', className)}
      aria-keyshortcuts="f"
      title={`${label} (f)`}
      onClick={ctx.toggle}
      data-testid="flow-fullscreen-toggle"
    >
      <Icon className="size-4" aria-hidden />
      <span className="ml-1 hidden sm:inline">{label}</span>
      <span className="sr-only sm:hidden">{label}</span>
    </Button>
  )
}
