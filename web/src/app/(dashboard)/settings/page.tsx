'use client'

import { useMemo, useState } from 'react'
import Link from 'next/link'
import { Search } from 'lucide-react'
import { Main } from '@/components/layout'
import { Input } from '@/components/ui/input'
import { PageHeader, SettingsSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useSettingsNav } from '@/hooks/use-settings-nav'
import { searchSettings } from '@/config/settings-search'

/**
 * /settings: a search box over every page and the settings inside them, then
 * every settings page the user can open, grouped as in the settings rail and
 * built from the same config (src/config/settings-nav.ts), so this page, the
 * rail and ⌘K never disagree. Everyone sees at least "My account", so the
 * user-menu "Settings" link never ends on Access Denied.
 */
export default function SettingsIndexPage() {
  const { t } = useTranslation()
  const groups = useSettingsNav()
  const [query, setQuery] = useState('')
  const results = useMemo(
    () =>
      searchSettings(
        groups.flatMap((g) => g.items),
        query
      ),
    [groups, query]
  )
  const searching = query.trim() !== ''
  const searchLabel = t('settings.search.label', 'Search settings')

  return (
    <Main>
      <PageHeader
        title={t('nav.item.settings', 'Settings')}
        description={t(
          'settings.overview.description',
          'Your account, and how your organization is set up.'
        )}
      />
      <div className="relative mt-5 max-w-2xl">
        <Search
          aria-hidden
          className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setQuery('')
          }}
          placeholder={t(
            'settings.search.placeholder',
            'Search settings: two-factor, IP allowlist, Slack…'
          )}
          aria-label={searchLabel}
          aria-controls="settings-search-results"
          className="h-10 ps-9"
        />
      </div>

      {searching ? (
        <div id="settings-search-results" className="mt-5">
          <p role="status" className="mb-2 text-sm text-muted-foreground">
            {results.length === 0
              ? t('settings.noMatch', 'No settings match your filter.')
              : t('settings.search.count', '{count} results', { count: results.length })}
          </p>
          <ul className="divide-y rounded-xl border">
            {results.map((r) => {
              const Icon = r.icon
              return (
                <li key={r.key}>
                  <Link
                    href={r.href}
                    className="flex items-center gap-3 px-4 py-3 hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none"
                  >
                    <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-medium">{r.label}</span>
                      <span className="block truncate text-xs text-muted-foreground">
                        {r.context}
                      </span>
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ) : (
        <div className="mt-6 space-y-7">
          {groups.map((group) => (
            <SettingsSection key={group.id} id={`settings-${group.id}`} title={group.label}>
              <ul className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
                {group.items.map((item) => {
                  const Icon = item.icon
                  return (
                    <li key={item.id}>
                      <Link
                        href={item.url}
                        className="flex items-start gap-3 rounded-lg px-2 py-2 hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none"
                      >
                        <Icon
                          className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                          aria-hidden
                        />
                        <span className="min-w-0">
                          <span className="block text-sm font-medium">
                            {item.label}
                            {item.badge && (
                              <span className="ms-2 text-xs font-normal text-muted-foreground">
                                {t('settings.badge.soon', 'Soon')}
                              </span>
                            )}
                          </span>
                          <span className="line-clamp-2 text-xs text-muted-foreground">
                            {item.desc}
                          </span>
                        </span>
                      </Link>
                    </li>
                  )
                })}
              </ul>
            </SettingsSection>
          ))}
        </div>
      )}
    </Main>
  )
}
