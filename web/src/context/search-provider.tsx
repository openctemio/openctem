'use client'

import { createContext, useContext, useEffect, useMemo, useState, type ComponentType } from 'react'
import dynamic from 'next/dynamic'

// The command palette (cmdk, the full nav and settings lists) loads the first
// time it opens instead of with every dashboard page: it is in the shell, so a
// static import put it in the JS of every route.
const CommandMenu = dynamic(() => import('@/components/command-menu').then((m) => m.CommandMenu), {
  ssr: false,
})

type SearchContextType = {
  open: boolean
  setOpen: React.Dispatch<React.SetStateAction<boolean>>
}

const SearchContext = createContext<SearchContextType | null>(null)

type SearchProviderProps = {
  children: React.ReactNode
  /**
   * The palette to open; the tenant app's by default. The admin console
   * passes its own (console pages, organizations), so both shells share one
   * shortcut and one search button.
   */
  menu?: ComponentType
}

export function SearchProvider({ children, menu: Menu = CommandMenu }: SearchProviderProps) {
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((open) => !open)
      }
    }
    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [])

  // Mounted from the first open on, so closing keeps its exit animation and
  // reopening is instant.
  const [opened, setOpened] = useState(false)
  if (open && !opened) setOpened(true)

  const value = useMemo(() => ({ open, setOpen }), [open])

  return (
    <SearchContext.Provider value={value}>
      {children}
      {opened && <Menu />}
    </SearchContext.Provider>
  )
}

export const useSearch = () => {
  const searchContext = useContext(SearchContext)

  if (!searchContext) {
    throw new Error('useSearch has to be used within SearchProvider')
  }

  return searchContext
}
