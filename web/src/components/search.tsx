import { useEffect, useState } from 'react'
import { SearchIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSearch } from '@/context/search-provider'
import { Button } from './ui/button'
import { DecorativeText } from './ui/decorative-text'
import { useTranslation } from '@/context/i18n-provider'
import { HEADER_ICON_COLOUR, PHONE_TOUCH_SQUARE } from '@/components/layout/header-controls'

type SearchProps = {
  className?: string
  type?: React.HTMLInputTypeAttribute
  placeholder?: string
}

export function Search({ className = '', placeholder }: SearchProps) {
  const { setOpen } = useSearch()
  const { t } = useTranslation()
  const label = placeholder ?? t('nav.header.searchOrRun', 'Search or run a command')
  // The shortcut as this platform writes it (read after mount: the server
  // does not know the platform).
  const [mac, setMac] = useState(false)
  useEffect(() => {
    setMac(/Mac|iPhone|iPad/.test(navigator.platform))
  }, [])
  return (
    <Button
      variant="ghost"
      className={cn(
        'group hover:bg-hov hover:text-foreground relative rounded-md font-normal shadow-none',
        // Below 1024px an icon-only ghost square in the ink colour as the other
        // top-bar icons (32; 36 below 768px with a 20 px icon and a 44 x 44
        // touch area, as every phone-bar control); from 1024 a field whose
        // placeholder text and icon are dim.
        HEADER_ICON_COLOUR,
        'lg:text-fg-dim',
        'size-control max-md:size-control-touch justify-center p-0',
        PHONE_TOUCH_SQUARE,
        // 1024-1279: 200 wide with the label; from 1280: 420 with the Ctrl K hint.
        // Transparent with the field border (shell package (c)).
        'lg:border-border-strong lg:text-dense lg:w-50 lg:justify-start lg:gap-2 lg:border lg:px-2 xl:w-105',
        className
      )}
      onClick={() => setOpen(true)}
      // Below lg the button is an icon: the label is its only accessible name.
      aria-label={label}
      title={label}
      aria-keyshortcuts={mac ? 'Meta+K' : 'Control+K'}
    >
      <SearchIcon aria-hidden="true" className="size-4 shrink-0 max-md:size-5" strokeWidth={1.75} />
      {/* 1024-1279 (200 wide): the short label, so it fits in every language;
          the full label from 1280 and always as the accessible name. */}
      <span className="hidden min-w-0 flex-1 truncate text-start lg:inline xl:hidden">
        {placeholder ?? t('nav.header.searchShort', 'Search')}
      </span>
      <span className="hidden min-w-0 flex-1 truncate text-start xl:inline">{label}</span>
      <DecorativeText
        as="kbd"
        text={mac ? '⌘K' : 'Ctrl K'}
        className="bg-muted text-muted-foreground pointer-events-none hidden h-5 shrink-0 items-center rounded border px-1.5 font-mono text-cap select-none xl:flex"
      />
    </Button>
  )
}
