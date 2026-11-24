'use client'

import { useDocsHref } from '@/context/brand-provider'
import React from 'react'
import { usePathname, useRouter } from 'next/navigation'
import {
  BookOpen,
  Bug,
  ChevronRight,
  CircleUserRound,
  ClipboardList,
  Eye,
  FileText,
  Laptop,
  Loader2,
  Moon,
  Search,
  Server,
  Settings,
  ShieldAlert,
  Sun,
} from 'lucide-react'
import { useSearch } from '@/context/search-provider'
import { useTheme } from 'next-themes'
import {
  CommandDialog,
  CommandEmpty,
  CommandFooter,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandKeyHint,
  CommandList,
} from '@/components/ui/command'
import { groupTitleKey, navItemKey } from '@/components/layout/nav-labels'
// Use centralized sidebar data from features
import { sidebarData } from '@/config/sidebar-data'
import { useFilteredSidebarData } from '@/lib/permissions'
import { anchorHref, announceSettingsAnchor } from '@/config/settings-search'
import { useSettingsNav } from '@/hooks/use-settings-nav'
import { useTranslation } from '@/context/i18n-provider'
import { commandFilter } from '@/lib/command-filter'
import { DOCS_URL } from '@/lib/docs-links'
import { safeHref } from '@/lib/safe-href'
import { useHelpEntries } from '@/hooks/use-help-entries'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { useFindingQuickViews } from '@/features/findings/api/use-quick-views'
import {
  QUICK_VIEW_LABELS,
  knownQuickViews,
  quickViewLink,
  quickViewLabelKey,
  type QuickViewKey,
} from '@/features/findings/lib/quick-views'
import { useSavedViews } from '@/features/saved-views/api/use-saved-views'
import { useCreateActions } from '@/hooks/use-create-actions'
import { usePaletteSearch } from '@/features/command-palette/use-palette-search'
import type { PaletteEntityKind } from '@/features/command-palette/palette-search'
import { pickRecentPages, readRecentPages } from '@/features/command-palette/recent-pages'
import { formatNumber } from '@/lib/app-locale'

const KIND_ICON: Record<PaletteEntityKind, typeof Bug> = {
  finding: ShieldAlert,
  asset: Server,
  task: ClipboardList,
}

/**
 * The main sections listed under "Go to" while the search is empty, in this
 * order; one the caller cannot open (not in the filtered sidebar) is left out.
 */
const GO_TO_URLS = [
  '/',
  '/my-work',
  '/findings',
  '/vulnerabilities',
  '/assets',
  '/scans',
  '/remediation',
  '/reports',
] as const

/** A page the palette can open: its label, the label of its parent, its icon. */
interface PageEntry {
  label: string
  parent?: string
  icon?: React.ElementType
}

/** A page row's content: its icon (muted), then "Parent > Page" or the page alone. */
function PageLabel({ entry }: { entry: PageEntry }) {
  const Icon = entry.icon ?? FileText
  return (
    <>
      <Icon aria-hidden />
      <span className="flex min-w-0 items-center gap-1">
        {entry.parent && (
          <>
            <span className="text-muted-foreground truncate">{entry.parent}</span>
            <ChevronRight className="size-3.5 shrink-0" aria-hidden />
          </>
        )}
        <span className="truncate">{entry.label}</span>
      </span>
    </>
  )
}

export function CommandMenu() {
  const docsHref = useDocsHref()
  const helpEntries = useHelpEntries()
  const router = useRouter()
  const pathname = usePathname()
  const { setTheme } = useTheme()
  const { open, setOpen } = useSearch()

  // Filter sidebar data based on user permissions and modules
  const { data: filteredSidebarData } = useFilteredSidebarData(sidebarData)
  // Settings pages live in their own nav (the settings rail), not in
  // sidebarData, so index them here or they vanish from search.
  const settingsGroups = useSettingsNav()
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const [query, setQuery] = React.useState('')
  // Read when the palette opens: the pages opened since are listed.
  const [recentPaths, setRecentPaths] = React.useState<string[]>([])
  React.useEffect(() => {
    if (open) setRecentPaths(readRecentPages())
    else setQuery('')
  }, [open])
  const typed = query.trim()
  // An empty search shows the short start list: Recent, Go to, Create.
  const browsing = typed === ''
  // '>' lists the commands only.
  const commandMode = typed.startsWith('>')
  const searching = !browsing && !commandMode
  const canFindings = hasPermission(Permission.FindingsRead)
  // The vulnerability page is offered only when the sidebar (permission and
  // module gate) offers it, so the palette never links a page the caller
  // cannot open.
  const canVulnerabilityPage = filteredSidebarData.navGroups.some((g) =>
    g.items.some((i) => 'url' in i && i.url === '/vulnerabilities')
  )
  const search = usePaletteSearch(open ? query : '', {
    findings: canFindings,
    assets: hasPermission(Permission.AssetsRead),
    tasks: hasPermission(Permission.RemediationRead),
  })
  // Views and saved views are read only while the palette is open.
  const { data: quickViewData } = useFindingQuickViews(open && canFindings)
  const { views: savedViews } = useSavedViews('findings', open && canFindings)
  const quickViews = knownQuickViews(quickViewData?.views)
  const includeInfo = quickViewData?.include_informational ?? false
  // Open-a-form commands only: every write stays on its page, behind that
  // page's own confirmation and step-up. The same list, with the same gates,
  // as the header's Create menu (src/hooks/use-create-actions.ts).
  const createActions = useCreateActions()
  const commands = createActions.map((a) => ({
    key: a.id,
    label: t(a.labelKey, a.label),
    href: a.href,
    icon: a.icon,
  }))
  const kindHeading: Record<PaletteEntityKind, string> = {
    finding: t('nav.palette.group.findings', 'Findings'),
    asset: t('nav.palette.group.assets', 'Assets'),
    task: t('nav.palette.group.tasks', 'Remediation tasks'),
  }
  const navLabel = React.useCallback((title: string) => t(navItemKey(title), title), [t])

  // Every page the caller may open now (the filtered sidebar and settings
  // navigation), by path: the Recent and Go to rows are looked up here, so
  // a page the caller lost access to is never offered.
  const pages = React.useMemo(() => {
    const index = new Map<string, PageEntry>()
    for (const group of filteredSidebarData.navGroups) {
      for (const item of group.items) {
        if ('url' in item) {
          const label = navLabel(item.title)
          index.set(item.url.toString(), { label, icon: item.icon })
          for (const section of item.sections ?? []) {
            if (section.href === item.url || index.has(section.href)) continue
            index.set(section.href, {
              label: section.labelKey ? t(section.labelKey, section.label) : section.label,
              parent: label,
              icon: section.icon ?? item.icon,
            })
          }
        } else {
          for (const sub of item.items ?? []) {
            const url = sub.url.toString()
            if (!index.has(url))
              index.set(url, {
                label: navLabel(sub.title),
                parent: navLabel(item.title),
                icon: sub.icon ?? item.icon,
              })
          }
        }
      }
    }
    index.set('/account', {
      label: t('userMenu.accountSettings', 'Account settings'),
      icon: CircleUserRound,
    })
    index.set('/settings', {
      label: t('nav.item.organizationSettings', 'Organization settings'),
      icon: Settings,
    })
    for (const group of settingsGroups)
      for (const item of group.items)
        if (!index.has(item.url))
          index.set(item.url, { label: item.label, parent: group.label, icon: item.icon })
    return index
  }, [filteredSidebarData, settingsGroups, navLabel, t])
  const recent = pickRecentPages(recentPaths, pages, pathname)
  const recentUrls = new Set(recent.map((r) => r.url))
  const goTo = GO_TO_URLS.filter((u) => pages.has(u) && !recentUrls.has(u)).map((url) => ({
    url,
    ...(pages.get(url) as PageEntry),
  }))

  const runCommand = React.useCallback(
    (command: () => unknown) => {
      setOpen(false)
      command()
    },
    [setOpen]
  )
  const go = (href: string) => runCommand(() => router.push(href))

  const createGroup = commands.length > 0 && (
    <CommandGroup heading={t('nav.palette.group.create', 'Create')}>
      {commands.map((c) => (
        <CommandItem
          key={c.key}
          value={c.label}
          keywords={['new', 'create', '>']}
          onSelect={() => go(c.href)}
        >
          <c.icon aria-hidden />
          <span className="truncate">{c.label}</span>
        </CommandItem>
      ))}
    </CommandGroup>
  )

  return (
    <CommandDialog
      modal
      open={open}
      onOpenChange={setOpen}
      filter={(value, q, keywords) => commandFilter(value, q.replace(/^\s*>\s*/, ''), keywords)}
      title={t('nav.palette.title', 'Search or go to')}
      description={t(
        'nav.palette.description',
        'Go to a page or view, search findings, assets and tasks, or type > for commands'
      )}
      footer={
        <CommandFooter>
          <CommandKeyHint keys={[['↑'], ['↓']]}>
            {t('nav.palette.hint.move', 'Move')}
          </CommandKeyHint>
          <CommandKeyHint keys={[['Enter']]}>{t('nav.palette.hint.open', 'Open')}</CommandKeyHint>
          <CommandKeyHint keys={[['esc']]}>{t('nav.palette.hint.close', 'Close')}</CommandKeyHint>
          <CommandKeyHint keys={[['mod', 'K']]} className="ms-auto">
            {t('nav.palette.hint.toggle', 'Open from any page')}
          </CommandKeyHint>
        </CommandFooter>
      }
    >
      <CommandInput
        value={query}
        onValueChange={setQuery}
        placeholder={t(
          'nav.palette.placeholder',
          'Search pages, findings, assets… or type > for commands'
        )}
      />
      <CommandList>
        <CommandEmpty>
          {search.loading
            ? t('nav.palette.searching', 'Searching')
            : t('nav.palette.empty', 'No results found.')}
        </CommandEmpty>
        {browsing && recent.length > 0 && (
          <CommandGroup heading={t('nav.palette.group.recent', 'Recent')}>
            {recent.map((r) => (
              <CommandItem
                key={`recent-${r.url}`}
                value={`recent ${r.url}`}
                onSelect={() => go(r.url)}
              >
                <PageLabel entry={r} />
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {browsing && goTo.length > 0 && (
          <CommandGroup heading={t('nav.palette.group.goTo', 'Go to')}>
            {goTo.map((r) => (
              <CommandItem key={`goto-${r.url}`} value={`goto ${r.url}`} onSelect={() => go(r.url)}>
                <PageLabel entry={r} />
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {createGroup}
        {searching && (quickViews.length > 0 || savedViews.length > 0) && (
          <CommandGroup heading={t('nav.palette.group.views', 'Findings views')}>
            {quickViews.map((v) => {
              const label = t(quickViewLabelKey(v.key), QUICK_VIEW_LABELS[v.key as QuickViewKey])
              return (
                <CommandItem
                  key={`qv-${v.key}`}
                  value={label}
                  keywords={[t('nav.palette.group.views', 'Findings views')]}
                  onSelect={() => go(quickViewLink(v, includeInfo))}
                >
                  <Eye aria-hidden />
                  <span className="truncate">{label}</span>
                  {typeof v.count === 'number' && (
                    <span className="text-muted-foreground ms-auto text-xs tabular-nums">
                      {formatNumber(v.count)}
                    </span>
                  )}
                </CommandItem>
              )
            })}
            {savedViews.map((v) => (
              <CommandItem
                key={`sv-${v.id}`}
                value={`${v.name} (${v.id.slice(0, 8)})`}
                keywords={[t('nav.palette.savedView', 'Saved view')]}
                onSelect={() => go(`/findings?view=${encodeURIComponent(v.id)}`)}
              >
                <Eye aria-hidden />
                <span dir="auto" className="truncate [unicode-bidi:isolate]">
                  {v.name}
                </span>
                <span className="text-muted-foreground ms-auto shrink-0 text-xs">
                  {t('nav.palette.savedView', 'Saved view')}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {searching &&
          filteredSidebarData.navGroups.map((group, gi) => (
            <CommandGroup
              key={group.title || `untitled-${gi}`}
              heading={group.title ? t(groupTitleKey(group.title), group.title) : undefined}
            >
              {group.items.map((navItem, i) => {
                if ('url' in navItem) {
                  const label = navLabel(navItem.title)
                  return (
                    <React.Fragment key={`${navItem.url}-${i}`}>
                      <CommandItem
                        value={label}
                        keywords={[navItem.title, ...(navItem.keywords ?? [])]}
                        onSelect={() => go(navItem.url.toString())}
                      >
                        <PageLabel entry={{ label, icon: navItem.icon }} />
                      </CommandItem>
                      {/* In-page section tabs (e.g. Exposures > Secrets): not
                          sidebar rows, but still reachable from search. The tab
                          at the item's own url is the item itself. */}
                      {navItem.sections
                        ?.filter((section) => section.href !== navItem.url)
                        .map((section) => {
                          const sectionLabel = section.labelKey
                            ? t(section.labelKey, section.label)
                            : section.label
                          return (
                            <CommandItem
                              key={section.href}
                              // Label first so "secrets" ranks it as a label
                              // match; the section name is a keyword.
                              value={`${sectionLabel} (${label})`}
                              keywords={[navItem.title, section.label, ...(section.keywords ?? [])]}
                              onSelect={() => go(section.href)}
                            >
                              <PageLabel
                                entry={{
                                  label: sectionLabel,
                                  parent: label,
                                  icon: section.icon ?? navItem.icon,
                                }}
                              />
                            </CommandItem>
                          )
                        })}
                    </React.Fragment>
                  )
                }

                return navItem.items?.map((subItem, i) => (
                  <CommandItem
                    key={`${navItem.title}-${subItem.url}-${i}`}
                    value={`${navItem.title}-${subItem.url}`}
                    onSelect={() => go(subItem.url.toString())}
                  >
                    <PageLabel
                      entry={{
                        label: navLabel(subItem.title),
                        parent: navLabel(navItem.title),
                        icon: subItem.icon ?? navItem.icon,
                      }}
                    />
                  </CommandItem>
                ))
              })}
            </CommandGroup>
          ))}
        {searching && (
          <CommandGroup heading={t('nav.item.settings', 'Settings')}>
            {/* The two settings areas: the person's account (outside the
                organization shell) and the organization's overview, which
                the sidebar footer's row opens. */}
            <CommandItem
              value={t('userMenu.accountSettings', 'Account settings')}
              keywords={['Account', 'Profile', 'Password', 'Two-factor', 'Preferences']}
              onSelect={() => {
                runCommand(() => router.push('/account'))
              }}
            >
              <CircleUserRound aria-hidden />
              <span className="truncate">{t('userMenu.accountSettings', 'Account settings')}</span>
            </CommandItem>
            <CommandItem
              value={t('nav.item.organizationSettings', 'Organization settings')}
              keywords={['Settings', 'Organization']}
              onSelect={() => {
                runCommand(() => router.push('/settings'))
              }}
            >
              <Settings aria-hidden />
              <span className="truncate">
                {t('nav.item.organizationSettings', 'Organization settings')}
              </span>
            </CommandItem>
            {settingsGroups.flatMap((group) =>
              group.items.map((item) => (
                <CommandItem
                  key={`settings-${item.id}`}
                  // The label alone, plus the group and search keywords: cmdk
                  // matches fuzzily, so a url or a description in the value
                  // makes nearly every item match every query.
                  value={`${item.label} (${group.label})`}
                  keywords={[item.title, group.title, ...(item.keywords ?? [])]}
                  onSelect={() => go(item.url)}
                >
                  <PageLabel entry={{ label: item.label, parent: group.label, icon: item.icon }} />
                </CommandItem>
              ))
            )}
            {/* The settings inside pages (settings-nav.ts anchors): opening one
                scrolls to it and outlines it. */}
            {settingsGroups.flatMap((group) =>
              group.items.flatMap((item) =>
                item.searchAnchors.map((a) => (
                  <CommandItem
                    key={`settings-${item.id}-${a.id}`}
                    value={`${a.label} (${item.label})`}
                    keywords={[a.title, ...(a.keywords ?? [])]}
                    onSelect={() => {
                      runCommand(() => {
                        router.push(anchorHref(item.url, a.id))
                        announceSettingsAnchor()
                      })
                    }}
                  >
                    <PageLabel entry={{ label: a.label, parent: item.label, icon: item.icon }} />
                  </CommandItem>
                ))
              )
            )}
          </CommandGroup>
        )}
        {searching && (
          <CommandGroup heading={t('help.menu', 'Help')}>
            <CommandItem
              value={t('help.documentation', 'Documentation')}
              keywords={['Help', 'Docs']}
              onSelect={() => {
                runCommand(() => window.open(docsHref(DOCS_URL), '_blank', 'noopener,noreferrer'))
              }}
            >
              <BookOpen aria-hidden />
              <span className="truncate">{t('help.documentation', 'Documentation')}</span>
            </CommandItem>
            {helpEntries.map((entry) => (
              <CommandItem
                key={entry.id}
                value={entry.label}
                keywords={['Help', ...entry.keywords]}
                onSelect={() => {
                  // The same link the Help menu opens, through the same encoder.
                  const href = safeHref(entry.href, {
                    allowRelative: false,
                    allowMailto: entry.allowMailto,
                  })
                  if (!href) return
                  runCommand(() => {
                    if (href.startsWith('mailto:')) window.location.href = href
                    else window.open(href, '_blank', 'noopener,noreferrer')
                  })
                }}
              >
                <entry.icon aria-hidden />
                <span className="truncate">{entry.label}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {searching && search.cve && (canFindings || canVulnerabilityPage) && (
          <CommandGroup forceMount heading={t('nav.palette.group.vulnerability', 'Vulnerability')}>
            {canVulnerabilityPage && (
              <CommandItem
                forceMount
                value={`cve open ${search.cve}`}
                onSelect={() => go(`/vulnerabilities/${encodeURIComponent(search.cve as string)}`)}
              >
                <Bug aria-hidden />
                {t('nav.palette.cveOpen', 'Open {cve}', { cve: search.cve })}
              </CommandItem>
            )}
            {canFindings && (
              <CommandItem
                forceMount
                value={`cve ${search.cve}`}
                onSelect={() => go(`/findings?cve_id=${encodeURIComponent(search.cve as string)}`)}
              >
                <Search aria-hidden />
                {t('nav.palette.cveFindings', 'Findings for {cve}', { cve: search.cve })}
              </CommandItem>
            )}
          </CommandGroup>
        )}
        {searching &&
          (['finding', 'asset', 'task'] as PaletteEntityKind[]).map((kind) => {
            const rows = search.results.filter((r) => r.kind === kind)
            if (rows.length === 0) return null
            const Icon = KIND_ICON[kind]
            return (
              <CommandGroup key={kind} forceMount heading={kindHeading[kind]}>
                {rows.map((r) => (
                  <CommandItem
                    key={`${kind}-${r.id}`}
                    forceMount
                    value={`${kind} ${r.id}`}
                    onSelect={() => go(r.href)}
                  >
                    <Icon aria-hidden />
                    <span dir="auto" className="truncate [unicode-bidi:isolate]">
                      {r.label}
                    </span>
                  </CommandItem>
                ))}
              </CommandGroup>
            )
          })}
        {searching && search.loading && (
          <div
            role="status"
            className="text-muted-foreground flex items-center gap-2 px-4 py-2 text-xs"
          >
            <Loader2 className="size-3.5 animate-spin motion-reduce:animate-none" aria-hidden />
            {t('nav.palette.searching', 'Searching')}
          </div>
        )}
        {!browsing && (
          <CommandGroup heading={t('nav.palette.group.theme', 'Theme')}>
            <CommandItem
              value={t('nav.palette.theme.light', 'Light theme')}
              onSelect={() => runCommand(() => setTheme('light'))}
            >
              <Sun aria-hidden />
              <span>{t('nav.palette.theme.light', 'Light theme')}</span>
            </CommandItem>
            <CommandItem
              value={t('nav.palette.theme.dark', 'Dark theme')}
              onSelect={() => runCommand(() => setTheme('dark'))}
            >
              <Moon aria-hidden />
              <span>{t('nav.palette.theme.dark', 'Dark theme')}</span>
            </CommandItem>
            <CommandItem
              value={t('nav.palette.theme.system', 'System theme')}
              onSelect={() => runCommand(() => setTheme('system'))}
            >
              <Laptop aria-hidden />
              <span>{t('nav.palette.theme.system', 'System theme')}</span>
            </CommandItem>
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  )
}
