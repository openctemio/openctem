import type * as React from 'react'

/**
 * Where a control sits decides its height, not the call site (control scale,
 * web/docs/ui-style-contract.md): 32px by default, 28px for the small sizes in
 * a dense place (table rows, the bulk action bar; drawers and property panels
 * follow in their page waves), 36px on entry pages, 44px below 768px.
 *
 * A dense place carries `data-control-density="dense"`; the small sizes of the
 * kit (`h-control-dense`, Button `sm` and `icon-sm`, SelectTrigger `sm`) read
 * it through CSS (src/styles/theme.css), so they render 32px anywhere else.
 * No context and no hook: kit controls stay usable in server components.
 */
export const DENSE_ATTRS = { 'data-control-density': 'dense' } as const

/** Marks its children as a dense place without adding a layout box. */
export function DensityScope({ children }: { children: React.ReactNode }) {
  return (
    <div data-control-density="dense" className="contents">
      {children}
    </div>
  )
}

/** An entry page without the app sidebar: every control 36px (44 below 768px). */
export function EntryScope({ children }: { children: React.ReactNode }) {
  return (
    <div data-control-scale="entry" className="contents">
      {children}
    </div>
  )
}
