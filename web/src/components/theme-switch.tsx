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

export function ThemeSwitch() {
  const { theme, setTheme, systemTheme } = useTheme()
  const { t } = useTranslation()
  const names: Record<string, string> = {
    light: t('nav.header.themeLight', 'Light'),
    dark: t('nav.header.themeDark', 'Dark'),
    system: t('nav.header.themeSystem', 'System'),
  }

  useEffect(() => {
    const current =
      theme === 'system'
        ? systemTheme === 'dark'
          ? '#0a1628'
          : '#fafaf9'
        : theme === 'dark'
          ? '#0a1628'
          : '#fafaf9'

    const meta = document.querySelector("meta[name='theme-color']")
    if (meta) meta.setAttribute('content', current)
  }, [theme, systemTheme])

  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={HEADER_ICON_BUTTON}
          aria-label={t('nav.header.theme', 'Theme')}
          title={t('nav.header.theme', 'Theme')}
        >
          <Sun aria-hidden className="dark:hidden" />
          <Moon aria-hidden className="hidden dark:block" />
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className={cn(HEADER_MENU, 'w-40')}>
        {['light', 'dark', 'system'].map((mode) => (
          <DropdownMenuItem key={mode} onClick={() => setTheme(mode)}>
            {names[mode]}
            <Check aria-hidden className={cn('ms-auto', theme !== mode && 'invisible')} />
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
