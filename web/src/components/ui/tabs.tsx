'use client'

import * as React from 'react'
import * as TabsPrimitive from '@radix-ui/react-tabs'

import { cn } from '@/lib/utils'
import {
  EDGE_FADE_X_CLASS,
  TAB_CLASS,
  TAB_STRIP_CLASS,
  TabsCount,
  useTabStripScroll,
} from './tab-strip'

export { EDGE_FADE_X_CLASS, TAB_CLASS, TAB_STRIP_CLASS, useTabStripScroll }

function Tabs({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return (
    <TabsPrimitive.Root
      data-slot="tabs"
      className={cn('flex flex-col gap-2', className)}
      {...props}
    />
  )
}

/**
 * One tab style across the app: `line` (underline) is the default for every
 * Tabs. `segment` (pill) remains only as an explicit opt-in and is not used by
 * pages — mixing the two made tabs look different from screen to screen.
 * Equal-width layouts (`className="grid grid-cols-N"`) work with the underline
 * too: triggers centre their label in the cell.
 */
type TabsVariant = 'segment' | 'line'

const TabsVariantContext = React.createContext<TabsVariant>('line')

function TabsList({
  className,
  variant = 'line',
  ref,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.List> & { variant?: TabsVariant }) {
  const localRef = React.useRef<HTMLDivElement>(null)
  useTabStripScroll(localRef)
  const setRef = React.useCallback(
    (node: HTMLDivElement | null) => {
      localRef.current = node
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
    },
    [ref]
  )
  return (
    <TabsVariantContext.Provider value={variant}>
      <TabsPrimitive.List
        ref={setRef}
        data-slot="tabs-list"
        data-variant={variant}
        className={cn(
          variant === 'line'
            ? TAB_STRIP_CLASS
            : 'inline-flex h-control items-center justify-start rounded-md bg-muted p-[3px] text-muted-foreground overflow-x-auto no-scrollbar max-w-full',
          className
        )}
        {...props}
      />
    </TabsVariantContext.Provider>
  )
}

function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  const variant = React.useContext(TabsVariantContext)
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(
        variant === 'line'
          ? TAB_CLASS
          : 'inline-flex h-control-seg items-center justify-center whitespace-nowrap rounded-sm px-3 text-body font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm',
        className
      )}
      {...props}
    />
  )
}

function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return (
    <TabsPrimitive.Content
      data-slot="tabs-content"
      // A panel that holds controls (a toolbar, a table) is not a keyboard
      // stop itself: its controls are. Focused by a click or by script it
      // draws no ring, so a list never shows a frame around the whole panel
      // at rest. A panel of plain text passes `tabIndex={0}` and then shows
      // the ring on keyboard focus only.
      tabIndex={-1}
      className={cn(
        'flex-1 rounded-sm outline-none',
        props.tabIndex === 0 && 'focus-visible:ring-2 focus-visible:ring-ring',
        className
      )}
      {...props}
    />
  )
}

export { Tabs, TabsList, TabsTrigger, TabsContent, TabsCount }
