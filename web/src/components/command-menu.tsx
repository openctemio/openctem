'use client'

import { useDocsHref } from '@/context/brand-provider'
import React from 'react'
import { useRouter } from 'next/navigation'
import {
  ArrowRight,
  BookOpen,
  Bug,
  ChevronRight,
  ClipboardList,
  Eye,
  Laptop,
  Loader2,
  Moon,
  Plus,
  Search,
  Server,
  ShieldAlert,
  Sun,
} from 'lucide-react'
import { useSearch } from '@/context/search-provider'
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
// Use centralized sidebar data from features
import { sidebarData } from '@/config/sidebar-data'
import { useFilteredSidebarData } from '@/lib/permissions'
import { anchorHref, announceSettingsAnchor } from '@/config/settings-search'
import { useSettingsNav } from '@/hooks/use-settings-nav'
import { useTranslation } from '@/context/i18n-provider'
import { commandFilter } from '@/lib/command-filter'
import { DOCS_URL } from '@/lib/docs-links'
import { ScrollArea } from './ui/scroll-area'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { useFindingQuickViews } from '@/features/findings/api/use-quick-views'
import {
  QUICK_VIEW_LABELS,
  knownQuickViews,
  quickViewHref,
  quickViewLabelKey,
  type QuickViewKey,
} from '@/features/findings/lib/quick-views'
import { useSavedViews } from '@/features/saved-views/api/use-saved-views'
import { openFormHref } from '@/lib/open-form'
import { usePaletteSearch } from '@/features/command-palette/use-palette-search'
import type { PaletteEntityKind } from '@/features/command-palette/palette-search'

const KIND_ICON: Record<PaletteEntityKind, typeof Bug> = {
  finding: ShieldAlert,
  asset: Server,
  task: ClipboardList,
}

export function CommandMenu() {
  const docsHref = useDocsHref()
  const router = useRouter()
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
  React.useEffect(() => {
    if (!open) setQuery('')
  }, [open])
  // '>' lists the commands only.
  const commandMode = query.trimStart().startsWith('>')
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
  // page's own confirmation and step-up. Each is offered with its permission.
  const commands = [
    hasPermission(Permission.ScansWrite) && {
      key: 'new-scan',
      label: t('nav.palette.command.newScan', 'New scan'),
      href: openFormHref('/scans', 'scan'),
    },
    hasPermission('findings:write') &&
      hasPermission('assets:write') &&
      hasPermission('assets:import') && {
        key: 'import',
        label: t('nav.palette.command.import', 'Import results'),
        href: openFormHref('/findings', 'import'),
      },
    hasPermission(Permission.RemediationWrite) &&
      canFindings && {
        key: 'task',
        label: t('nav.palette.command.createTask', 'Create remediation task'),
        href: openFormHref('/remediation/tasks', 'task'),
      },
  ].filter(Boolean) as { key: string; label: string; href: string }[]
  const kindHeading: Record<PaletteEntityKind, string> = {
    finding: t('nav.palette.group.findings', 'Findings'),
    asset: t('nav.palette.group.assets', 'Assets'),
    task: t('nav.palette.group.tasks', 'Remediation tasks'),
  }

  const runCommand = React.useCallback(
    (command: () => unknown) => {
      setOpen(false)
      command()
    },
    [setOpen]
  )

  return (
    <CommandDialog
      modal
      open={open}
      onOpenChange={setOpen}
      filter={(value, q, keywords) => commandFilter(value, q.replace(/^\s*>\s*/, ''), keywords)}
      title={t('nav.palette.title', 'Search or go to')}
      description={t(
        'palette.description',
        'Go to a page or view, search findings, assets and tasks, or type > for commands'
      )}
    >
      <CommandInput
        value={query}
        onValueChange={setQuery}
        placeholder={t('nav.palette.placeholder', 'Search or go to, > for commands')}
      />
      <CommandList>
        <ScrollArea type="hover" className="h-80 pe-1">
          <CommandEmpty>
            {search.loading
              ? t('nav.palette.searching', 'Searching')
              : t('nav.palette.empty', 'No results found.')}
          </CommandEmpty>
          {commands.length > 0 && (
            <CommandGroup heading={t('nav.palette.group.commands', 'Commands')}>
              {commands.map((c) => (
                <CommandItem
                  key={c.key}
                  value={c.label}
                  keywords={['new', 'create', '>']}
                  onSelect={() => runCommand(() => router.push(c.href))}
                >
                  <Plus aria-hidden />
                  {c.label}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {!commandMode && (quickViews.length > 0 || savedViews.length > 0) && (
            <CommandGroup heading={t('nav.palette.group.views', 'Findings views')}>
              {quickViews.map((v) => {
                const label = t(quickViewLabelKey(v.key), QUICK_VIEW_LABELS[v.key as QuickViewKey])
                return (
                  <CommandItem
                    key={`qv-${v.key}`}
                    value={label}
                    keywords={[t('nav.palette.group.views', 'Findings views')]}
                    onSelect={() =>
                      runCommand(() => router.push(quickViewHref(v.params, includeInfo)))
                    }
                  >
                    <Eye aria-hidden />
                    <span className="truncate">{label}</span>
                    {typeof v.count === 'number' && (
                      <span className="text-muted-foreground ms-auto text-xs tabular-nums">
                        {v.count.toLocaleString()}
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
                  onSelect={() =>
                    runCommand(() => router.push(`/findings?view=${encodeURIComponent(v.id)}`))
                  }
                >
                  <Eye aria-hidden />
                  <span dir="auto" className="truncate [unicode-bidi:isolate]">
                    {v.name}
                  </span>
                  <span className="text-muted-foreground ms-auto text-xs">
                    {t('nav.palette.savedView', 'Saved view')}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {!commandMode &&
            filteredSidebarData.navGroups.map((group, gi) => (
              <CommandGroup key={group.title || `untitled-${gi}`} heading={group.title}>
                {group.items.map((navItem, i) => {
                  if ('url' in navItem)
                    return (
                      <React.Fragment key={`${navItem.url}-${i}`}>
                        <CommandItem
                          value={navItem.title}
                          keywords={navItem.keywords ? [...navItem.keywords] : undefined}
                          onSelect={() => {
                            runCommand(() => router.push(navItem.url.toString()))
                          }}
                        >
                          <div className="flex size-4 items-center justify-center">
                            <ArrowRight className="text-muted-foreground/80 size-2" />
                          </div>
                          {navItem.title}
                        </CommandItem>
                        {/* In-page section tabs (e.g. Exposures > Secrets): not
                          sidebar rows, but still reachable from search. The tab
                          at the item's own url is the item itself. */}
                        {navItem.sections
                          ?.filter((section) => section.href !== navItem.url)
                          .map((section) => (
                            <CommandItem
                              key={section.href}
                              // Label first so "secrets" ranks it as a label
                              // match; the section name is a keyword.
                              value={`${section.label} (${navItem.title})`}
                              keywords={[navItem.title, ...(section.keywords ?? [])]}
                              onSelect={() => {
                                runCommand(() => router.push(section.href))
                              }}
                            >
                              <div className="flex size-4 items-center justify-center">
                                <ArrowRight className="text-muted-foreground/80 size-2" />
                              </div>
                              {navItem.title} <ChevronRight /> {section.label}
                            </CommandItem>
                          ))}
                      </React.Fragment>
                    )

                  return navItem.items?.map((subItem, i) => (
                    <CommandItem
                      key={`${navItem.title}-${subItem.url}-${i}`}
                      value={`${navItem.title}-${subItem.url}`}
                      onSelect={() => {
                        runCommand(() => router.push(subItem.url.toString()))
                      }}
                    >
                      <div className="flex size-4 items-center justify-center">
                        <ArrowRight className="text-muted-foreground/80 size-2" />
                      </div>
                      {navItem.title} <ChevronRight /> {subItem.title}
                    </CommandItem>
                  ))
                })}
              </CommandGroup>
            ))}
          {!commandMode && (
            <CommandGroup heading={t('nav.item.settings', 'Settings')}>
              {/* The overview, which the sidebar footer's Settings row opens. */}
              <CommandItem
                value={t('nav.item.settings', 'Settings')}
                keywords={['Settings']}
                onSelect={() => {
                  runCommand(() => router.push('/settings'))
                }}
              >
                <div className="flex size-4 items-center justify-center">
                  <ArrowRight className="text-muted-foreground/80 size-2" />
                </div>
                {t('nav.item.settings', 'Settings')}
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
                    onSelect={() => {
                      runCommand(() => router.push(item.url))
                    }}
                  >
                    <div className="flex size-4 items-center justify-center">
                      <ArrowRight className="text-muted-foreground/80 size-2" />
                    </div>
                    {group.label} <ChevronRight /> {item.label}
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
                      <div className="flex size-4 items-center justify-center">
                        <ArrowRight className="text-muted-foreground/80 size-2" />
                      </div>
                      {item.label} <ChevronRight /> {a.label}
                    </CommandItem>
                  ))
                )
              )}
            </CommandGroup>
          )}
          {!commandMode && (
            <CommandGroup heading={t('help.menu', 'Help')}>
              <CommandItem
                value={t('help.documentation', 'Documentation')}
                keywords={['Help', 'Docs']}
                onSelect={() => {
                  runCommand(() => window.open(docsHref(DOCS_URL), '_blank', 'noopener,noreferrer'))
                }}
              >
                <BookOpen />
                <span>{t('help.documentation', 'Documentation')}</span>
              </CommandItem>
            </CommandGroup>
          )}
          {!commandMode && search.cve && (canFindings || canVulnerabilityPage) && (
            <CommandGroup
              forceMount
              heading={t('nav.palette.group.vulnerability', 'Vulnerability')}
            >
              {canVulnerabilityPage && (
                <CommandItem
                  forceMount
                  value={`cve open ${search.cve}`}
                  onSelect={() =>
                    runCommand(() =>
                      router.push(`/vulnerabilities/${encodeURIComponent(search.cve as string)}`)
                    )
                  }
                >
                  <Bug aria-hidden />
                  {t('nav.palette.cveOpen', 'Open {cve}', { cve: search.cve })}
                </CommandItem>
              )}
              {canFindings && (
                <CommandItem
                  forceMount
                  value={`cve ${search.cve}`}
                  onSelect={() =>
                    runCommand(() =>
                      router.push(`/findings?cve_id=${encodeURIComponent(search.cve as string)}`)
                    )
                  }
                >
                  <Search aria-hidden />
                  {t('nav.palette.cveFindings', 'Findings for {cve}', { cve: search.cve })}
                </CommandItem>
              )}
            </CommandGroup>
          )}
          {!commandMode &&
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
                      onSelect={() => runCommand(() => router.push(r.href))}
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
          {!commandMode && search.loading && (
            <div
              role="status"
              className="text-muted-foreground flex items-center gap-2 px-3 py-2 text-xs"
            >
              <Loader2 className="size-3.5 animate-spin motion-reduce:animate-none" aria-hidden />
              {t('nav.palette.searching', 'Searching')}
            </div>
          )}
          <CommandSeparator />
          <CommandGroup heading={t('nav.palette.group.theme', 'Theme')}>
            <CommandItem
              value={t('nav.palette.theme.light', 'Light theme')}
              onSelect={() => runCommand(() => setTheme('light'))}
            >
              <Sun /> <span>{t('nav.palette.theme.light', 'Light theme')}</span>
            </CommandItem>
            <CommandItem
              value={t('nav.palette.theme.dark', 'Dark theme')}
              onSelect={() => runCommand(() => setTheme('dark'))}
            >
              <Moon className="scale-90" />
              <span>{t('nav.palette.theme.dark', 'Dark theme')}</span>
            </CommandItem>
            <CommandItem
              value={t('nav.palette.theme.system', 'System theme')}
              onSelect={() => runCommand(() => setTheme('system'))}
            >
              <Laptop />
              <span>{t('nav.palette.theme.system', 'System theme')}</span>
            </CommandItem>
          </CommandGroup>
        </ScrollArea>
      </CommandList>
    </CommandDialog>
  )
}
