import { useEffect, useState } from 'react'
import { SearchIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSearch } from '@/context/search-provider'
import { Button } from './ui/button'
import { DecorativeText } from './ui/decorative-text'
import { useTranslation } from '@/context/i18n-provider'

type SearchProps = {
  className?: string
  type?: React.HTMLInputTypeAttribute
  placeholder?: string
}

export function Search({ className = '', placeholder }: SearchProps) {
  const { setOpen } = useSearch()
  const { t } = useTranslation()
  const label = placeholder ?? t('nav.header.searchOrGo', 'Search or go to')
  // The shortcut as this platform writes it (read after mount: the server
  // does not know the platform).
  const [mac, setMac] = useState(false)
  useEffect(() => {
    setMac(/Mac|iPhone|iPad/.test(navigator.platform))
  }, [])
  return (
    <Button
      variant="outline"
      className={cn(
        'bg-muted/25 group text-muted-foreground hover:bg-accent relative h-8 rounded-md text-sm font-normal shadow-none',
        // Mobile: icon only
        'w-8 justify-center p-0',
        // Small screens and up: show full search bar
        'sm:w-40 sm:justify-start sm:px-3 sm:pe-12',
        'md:flex-none lg:w-52 xl:w-64',
        className
      )}
      onClick={() => setOpen(true)}
      // Below sm the button is an icon: the label is its only accessible name.
      aria-label={label}
      aria-keyshortcuts={mac ? 'Meta+K' : 'Control+K'}
    >
      <SearchIcon
        aria-hidden="true"
        className="sm:absolute sm:start-1.5 sm:top-1/2 sm:-translate-y-1/2"
        size={16}
      />
      <span className="ms-4 hidden truncate sm:inline">{label}</span>
      <DecorativeText
        as="kbd"
        text={mac ? '⌘K' : 'Ctrl K'}
        className="bg-muted group-hover:bg-accent pointer-events-none absolute end-[0.3rem] top-[0.3rem] hidden h-5 items-center gap-1 rounded border px-1.5 font-mono text-xs font-medium opacity-100 select-none sm:flex"
      />
    </Button>
  )
}
