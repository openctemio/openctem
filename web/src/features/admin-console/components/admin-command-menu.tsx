'use client'

import React from 'react'
import { useRouter } from 'next/navigation'
import useSWR from 'swr'
import { ArrowRight, Building2, Laptop, Moon, Sun, User } from 'lucide-react'
import { useTheme } from 'next-themes'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useSearch } from '@/context/search-provider'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { commandFilter } from '@/lib/command-filter'
import { adminFetcher } from '../api/admin-client'
import { visibleAdminNav } from '../lib/admin-nav-visibility'
import { useAdmin } from './admin-console-shell'
import { PLATFORM_USER_SEARCH_MIN } from '../api/use-platform-users'
import type { AdminOrganizationList, Paged, PlatformUser } from '../types'

/** Searches shorter than this do not query organizations. */
export const ORG_SEARCH_MIN = 2
const ORG_SEARCH_LIMIT = 8

/**
 * The console's command palette (Cmd/Ctrl+K): every console page the
 * administrator's role can open, organizations by name or slug (searched on
 * the server, so any of thousands is one query away), and the theme.
 */
export function AdminCommandMenu() {
  const router = useRouter()
  const { setTheme } = useTheme()
  const { open, setOpen } = useSearch()
  const { t } = useTranslation()
  const admin = useAdmin()
  const [query, setQuery] = React.useState('')
  const q = useDebounce(query.trim(), 200)

  const orgPath =
    open && q.length >= ORG_SEARCH_MIN
      ? `/tenants?${new URLSearchParams({ search: q, page: '1', per_page: String(ORG_SEARCH_LIMIT) })}`
      : null
  const orgs = useSWR<AdminOrganizationList>(orgPath, adminFetcher, { keepPreviousData: true })
  // Accounts across organizations (Console > Users); the API needs 3+ characters.
  const userPath =
    open && q.length >= PLATFORM_USER_SEARCH_MIN
      ? `/platform-users?${new URLSearchParams({ q, page: '1', per_page: String(ORG_SEARCH_LIMIT) })}`
      : null
  const users = useSWR<Paged<PlatformUser>>(userPath, adminFetcher, { keepPreviousData: true })

  const run = React.useCallback(
    (fn: () => unknown) => {
      setOpen(false)
      setQuery('')
      fn()
    },
    [setOpen]
  )

  const sections = visibleAdminNav(admin.role)
  const orgResults = orgPath ? (orgs.data?.data ?? []) : []
  const userResults = userPath ? (users.data?.data ?? []) : []

  return (
    <CommandDialog
      modal
      open={open}
      onOpenChange={setOpen}
      filter={commandFilter}
      title={t('admin.palette.title', 'Search the console')}
      description={t('admin.palette.description', 'Go to a console page or an organization')}
    >
      <CommandInput
        placeholder={t('admin.palette.placeholder', 'Search pages, organizations and accounts...')}
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <ScrollArea type="hover" className="h-80 pe-1">
          <CommandEmpty>
            {orgs.isLoading && orgPath
              ? t('admin.palette.searching', 'Searching...')
              : t('admin.palette.empty', 'No results found.')}
          </CommandEmpty>
          {orgResults.length > 0 && (
            <CommandGroup heading={t('admin.nav.organizations', 'Organizations')}>
              {orgResults.map((org) => (
                <CommandItem
                  key={org.id}
                  // The server already matched name or slug; both are in the
                  // value so the client filter keeps the row.
                  value={`${org.name} ${org.slug} ${org.id}`}
                  keywords={[q]}
                  onSelect={() => run(() => router.push(`/admin/organizations/${org.id}`))}
                >
                  <Building2 className="text-muted-foreground" />
                  <span className="truncate">{org.name}</span>
                  <span className="ms-auto truncate text-xs text-muted-foreground">{org.slug}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {userResults.length > 0 && (
            <CommandGroup heading={t('admin.palette.accounts', 'Accounts')}>
              {userResults.map((u) => (
                <CommandItem
                  key={u.id}
                  value={`${u.email} ${u.name} ${u.id}`}
                  keywords={[q]}
                  onSelect={() => run(() => router.push(`/admin/users/${u.id}`))}
                >
                  <User className="text-muted-foreground" />
                  <span className="truncate">{u.name || u.email}</span>
                  <span className="ms-auto truncate text-xs text-muted-foreground">{u.email}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {sections.map((section, i) => (
            <CommandGroup
              key={section.title ?? `top-${i}`}
              heading={
                section.i18nKey
                  ? t(section.i18nKey, section.title)
                  : t('admin.palette.pages', 'Pages')
              }
            >
              {section.items.map((item) => {
                const label = t(item.i18nKey, item.title)
                return (
                  <CommandItem
                    key={item.url}
                    value={label}
                    keywords={[item.title, section.title ?? '', ...(item.keywords ?? [])]}
                    onSelect={() => run(() => router.push(item.url))}
                  >
                    <div className="flex size-4 items-center justify-center">
                      <ArrowRight className="size-2 text-muted-foreground/80" />
                    </div>
                    {label}
                  </CommandItem>
                )
              })}
            </CommandGroup>
          ))}
          <CommandSeparator />
          <CommandGroup heading={t('admin.palette.theme', 'Theme')}>
            <CommandItem value="Light theme" onSelect={() => run(() => setTheme('light'))}>
              <Sun /> <span>{t('admin.palette.light', 'Light')}</span>
            </CommandItem>
            <CommandItem value="Dark theme" onSelect={() => run(() => setTheme('dark'))}>
              <Moon className="scale-90" />
              <span>{t('admin.palette.dark', 'Dark')}</span>
            </CommandItem>
            <CommandItem value="System theme" onSelect={() => run(() => setTheme('system'))}>
              <Laptop />
              <span>{t('admin.palette.system', 'System')}</span>
            </CommandItem>
          </CommandGroup>
        </ScrollArea>
      </CommandList>
    </CommandDialog>
  )
}
