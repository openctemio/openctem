'use client'

import { useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Plus } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { useCreateActions, type CreateAction } from '@/hooks/use-create-actions'
import { CREATE_PREFIX, useCreateChords } from '@/hooks/use-create-chords'
import { cn } from '@/lib/utils'
import { HEADER_ICON_BUTTON, HEADER_MENU } from './header-controls'

/**
 * The top bar's Create menu (shell package 0.2): every "new" verb the caller
 * may use, each with its "n" chord. Not on a phone (the palette lists the same
 * commands there). With nothing allowed the button is not shown; the chords
 * of hidden actions do nothing.
 */
export function HeaderCreateMenu() {
  const { t } = useTranslation()
  const router = useRouter()
  const actions = useCreateActions()
  const run = useCallback((a: CreateAction) => router.push(a.href), [router])
  useCreateChords(actions, run)

  if (actions.length === 0) return null
  const label = t('nav.create.menu', 'Create')
  return (
    <DropdownMenu modal={false}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className={cn(HEADER_ICON_BUTTON, 'max-md:hidden')}
              aria-label={label}
              data-slot="header-create"
            >
              <Plus aria-hidden />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent side="bottom">{label}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className={cn(HEADER_MENU, 'w-58')}>
        {actions.map((a) => (
          <DropdownMenuItem key={a.id} asChild>
            <Link
              href={a.href}
              data-create={a.id}
              aria-keyshortcuts={a.chord ? `${CREATE_PREFIX} ${a.chord}` : undefined}
            >
              <a.icon aria-hidden />
              <span className="min-w-0 flex-1 truncate">{t(a.labelKey, a.label)}</span>
              {a.chord && (
                <DropdownMenuShortcut aria-hidden className="font-mono tracking-normal">
                  {`${CREATE_PREFIX} ${a.chord}`}
                </DropdownMenuShortcut>
              )}
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
