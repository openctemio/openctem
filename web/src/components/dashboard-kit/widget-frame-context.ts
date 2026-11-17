'use client'

/**
 * What a visualization tells the frame it sits in, and what the frame tells
 * it back: a chart with a table alternative registers itself, the frame's
 * menu switches the view, and the visualization draws the chosen one. Outside
 * a frame there is no context and the visualization keeps its own switch.
 */

import { createContext, useContext } from 'react'

export type WidgetBodyView = 'chart' | 'table'

export interface WidgetFrameContextValue {
  /** The view the person chose in the frame menu; null until they choose. */
  view: WidgetBodyView | null
  /** Called by a visualization that has both views, with the one it starts in. Returns the undo. */
  registerViews: (initial: WidgetBodyView) => () => void
}

export const WidgetFrameContext = createContext<WidgetFrameContextValue | null>(null)

export function useWidgetFrame(): WidgetFrameContextValue | null {
  return useContext(WidgetFrameContext)
}
