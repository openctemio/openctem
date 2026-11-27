'use client'

import { useMemo, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import Link from '@/components/link'
import { SettingsPage, SettingsSection, ListToolbar } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import {
  settingsSections,
  useSettingsNav,
  type VisibleSettingsGroup,
} from '@/hooks/use-settings-nav'
import { searchSettings } from '@/config/settings-search'
import { SettingsAttention } from '@/features/security-overview/components/settings-attention'

const ROW_LINK =
  'flex min-h-10 min-w-0 items-center gap-3 rounded-md px-2 py-2 hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none max-md:min-h-11'

/**
 * /settings: a search box over every page and the settings inside them, what
 * needs attention (the security overview in brief, for whoever may open it),
 * then every settings page the user can open, grouped as in the settings rail
 * and built from the same config (src/config/settings-nav.ts), so this page,
 * the rail and ⌘K never disagree. Everyone sees at least "Your membership", so the
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
  // The summary follows the same access as its nav item.
  const canSeeOverview = groups.some((g) => g.items.some((i) => i.id === 'security-overview'))
  const searchLabel = t('settings.search.label', 'Search settings')

  return (
    <SettingsPage
      title={t('nav.item.organizationSettings', 'Organization settings')}
      description={t(
        'settings.overview.descriptionOrg',
        'How your organization is set up, and you in it. Your profile, password and two-factor authentication are in your account settings.'
      )}
      banners={
        <ListToolbar
          className="max-w-settings"
          search={{
            value: query,
            onChange: setQuery,
            placeholder: t(
              'settings.search.placeholder',
              'Search settings: two-factor, IP allowlist, Slack…'
            ),
            label: searchLabel,
            // The results region exists only while searching; an aria-controls
            // naming a missing element is invalid (axe aria-valid-attr-value).
            inputProps: searching ? { 'aria-controls': 'settings-search-results' } : undefined,
          }}
        />
      }
    >
      {searching ? (
        <section
          id="settings-search-results"
          aria-label={t('settings.search.results', 'Search results')}
        >
          <p role="status" className="pb-2 text-dense text-muted-foreground">
            {results.length === 0
              ? t('settings.noMatch', 'No settings match your filter.')
              : t('settings.search.count', '{count} results', { count: results.length })}
          </p>
          <ul>
            {results.map((r) => {
              const Icon = r.icon
              return (
                <li key={r.key} className="border-t border-border-subtle">
                  <Link href={r.href} className={ROW_LINK}>
                    <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-body font-medium">{r.label}</span>
                      <span className="block truncate text-cap text-muted-foreground">
                        {r.context}
                      </span>
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </section>
      ) : (
        <>
          <SettingsAttention enabled={canSeeOverview} />
          {groups.map((group, i) => (
            <SettingsGroup key={group.id} group={group} first={i === 0} />
          ))}
        </>
      )}
    </SettingsPage>
  )
}

/**
 * One group of settings pages: its name, how many pages, and the pages as
 * links. Open on a desktop; on a phone only the first group starts open, so
 * the index is a short list of groups (the pages are one tap away).
 */
function SettingsGroup({ group, first }: { group: VisibleSettingsGroup; first: boolean }) {
  const { t } = useTranslation()
  const isMobile = useIsMobile()
  const [choice, setChoice] = useState<boolean | null>(null)
  const open = choice ?? (!isMobile || first)
  const headingId = `settings-${group.id}`
  return (
    <SettingsSection
      framed
      id={headingId}
      title={group.label}
      description={t('settings.overview.pages', '{count, plural, one {# page} other {# pages}}', {
        count: group.items.length,
      })}
      actions={
        <button
          type="button"
          aria-expanded={open}
          aria-controls={`${headingId}-pages`}
          onClick={() => setChoice(!open)}
          className="inline-flex size-control items-center justify-center rounded-md hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 max-md:size-control-touch"
          aria-label={
            open
              ? t('settings.overview.collapse', 'Hide the pages of {group}', {
                  group: group.label,
                })
              : t('settings.overview.expand', 'Show the pages of {group}', {
                  group: group.label,
                })
          }
        >
          <ChevronDown
            className={
              open ? 'size-4 rotate-180 transition-transform' : 'size-4 transition-transform'
            }
            aria-hidden
          />
        </button>
      }
    >
      <div
        id={`${headingId}-pages`}
        hidden={!open}
        className="space-y-3 border-t border-border-subtle py-3"
      >
        {settingsSections(group.items).map((chunk) => (
          <div key={chunk.section ?? ''}>
            {chunk.label && (
              <h3 className="mb-1 px-2 text-cap-m text-muted-foreground">{chunk.label}</h3>
            )}
            {/* Names only: the one-line descriptions are found by search
                  above and shown on hover, so the index stays short. */}
            <ul className="grid grid-cols-1 gap-x-6 @[36rem]:grid-cols-2 @[52rem]:grid-cols-3">
              {chunk.items.map((item) => {
                const Icon = item.icon
                return (
                  <li key={item.id}>
                    <Link href={item.url} title={item.desc} className={ROW_LINK}>
                      <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                      <span className="min-w-0 truncate text-body font-medium">{item.label}</span>
                      {item.badge && (
                        <span className="text-cap text-muted-foreground">
                          {t('settings.badge.soon', 'Soon')}
                        </span>
                      )}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>
    </SettingsSection>
  )
}
