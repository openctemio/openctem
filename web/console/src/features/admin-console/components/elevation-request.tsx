'use client'

import { createContext, useContext } from 'react'

/**
 * Opens the console's "Elevate for a while" dialog from anywhere in the shell
 * (the read-only notice on a page offers it next to what it unlocks). Null
 * outside the shell or when this administrator cannot elevate.
 */
export const ElevationRequestContext = createContext<(() => void) | null>(null)

export function useRequestElevation(): (() => void) | null {
  return useContext(ElevationRequestContext)
}
