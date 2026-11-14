'use client'

import { useEffect } from 'react'
import { Check, Moon, Sun } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTheme } from 'next-themes'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { HEADER_ICON_BUTTON, HEADER_MENU } from '@/components/layout/header-controls'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

const MODES = ['light', 'dark', 'system'] as const

/**
 * Light / Dark / System as menu rows with a check on the current one: the
 * theme menu of the top bar, and the "Theme" rows of the phone account menu
 * (the phone bar has no theme button).
 */
export function ThemeMenuItems() {
  const { theme, setTheme } = useTheme()
  const { t } = useTranslation()
  const names: Record<(typeof MODES)[number], string> = {
    light: t('nav.header.themeLight', 'Light'),
    dark: t('nav.header.themeDark', 'Dark'),
    system: t('nav.header.themeSystem', 'System'),
  }
  return MODES.map((mode) => (
    <DropdownMenuItem key={mode} onClick={() => setTheme(mode)}>
      {names[mode]}
      <Check aria-hidden className={cn('ms-auto', theme !== mode && 'invisible')} />
    </DropdownMenuItem>
  ))
}

/**
 * The top bar's theme menu. Below 768 px the app bar hides it (`className`)
 * but keeps it mounted, so it still sets the browser's theme colour.
 */
export function ThemeSwitch({ className }: { className?: string }) {
  const { resolvedTheme } = useTheme()
  const { t } = useTranslation()

  // The browser bar takes the page background token (theme.css `--background`,
  // drawn by body), read after the theme class has been applied.
  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      const meta = document.querySelector("meta[name='theme-color']")
      if (meta) meta.setAttribute('content', getComputedStyle(document.body).backgroundColor)
    })
    return () => cancelAnimationFrame(frame)
  }, [resolvedTheme])

  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn(HEADER_ICON_BUTTON, className)}
          aria-label={t('nav.header.theme', 'Theme')}
          title={t('nav.header.theme', 'Theme')}
        >
          <Sun aria-hidden className="dark:hidden" />
          <Moon aria-hidden className="hidden dark:block" />
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className={cn(HEADER_MENU, 'w-40')}>
        <ThemeMenuItems />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
