/**
 * Settings search: one index for the settings rail filter, the /settings
 * search box and the command palette (⌘K).
 *
 * It finds pages (title, description, group, keywords) and the settings
 * inside them (`anchors` in settings-nav.ts). A setting result links to
 * `<page url>#<anchor id>`; `useSettingsAnchorHighlight` (mounted in the
 * settings shell) scrolls to that element and outlines it for a moment.
 */
import type { LucideIcon } from 'lucide-react'
import type { SettingsNavItem } from './settings-nav'

/** Accent- and case-insensitive form of a text, for matching. */
export function foldSearchText(s: string): string {
  return s.normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'd').toLowerCase()
}

/** Every word of `query` occurs in one of `fields`. An empty query matches. */
export function matchesAllWords(query: string, fields: readonly string[]): boolean {
  const q = foldSearchText(query.trim())
  if (!q) return true
  const hay = foldSearchText(fields.join(' '))
  return q.split(/\s+/).every((word) => hay.includes(word))
}

export interface SearchableAnchor {
  id: string
  /** Translated title. */
  label: string
  /** English title. */
  title: string
  keywords?: string[]
}

export interface SearchableItem extends Pick<SettingsNavItem, 'id' | 'title' | 'url' | 'keywords'> {
  icon: LucideIcon
  label: string
  desc: string
  groupLabel: string
  groupTitle: string
  searchAnchors: SearchableAnchor[]
}

export interface SettingsSearchResult {
  /** Stable key: the item id, or `<item id>#<anchor id>`. */
  key: string
  itemId: string
  anchorId?: string
  /** What the result is: the page title, or the setting's title. */
  label: string
  /** Where it is: "Group" for a page, "Group › Page" for a setting. */
  context: string
  href: string
  icon: LucideIcon
}

/** The URL of a setting inside a page. */
export function anchorHref(url: string, anchorId: string): string {
  return `${url}#${anchorId}`
}

/**
 * Pages and settings that match `query`, in rail order; each page is followed
 * by its matching settings. A setting matches on its own title and keywords
 * only, so typing a page's name does not list every setting of that page.
 */
export function searchSettings(
  items: readonly SearchableItem[],
  query: string
): SettingsSearchResult[] {
  if (!query.trim()) return []
  const out: SettingsSearchResult[] = []
  for (const item of items) {
    if (
      matchesAllWords(query, [
        item.label,
        item.desc,
        item.groupLabel,
        item.title,
        item.groupTitle,
        ...(item.keywords ?? []),
      ])
    ) {
      out.push({
        key: item.id,
        itemId: item.id,
        label: item.label,
        context: item.groupLabel,
        href: item.url,
        icon: item.icon,
      })
    }
    for (const a of item.searchAnchors) {
      if (matchesAllWords(query, [a.label, a.title, ...(a.keywords ?? [])])) {
        out.push({
          key: `${item.id}#${a.id}`,
          itemId: item.id,
          anchorId: a.id,
          label: a.label,
          context: `${item.groupLabel} › ${item.label}`,
          href: anchorHref(item.url, a.id),
          icon: item.icon,
        })
      }
    }
  }
  return out
}

/** Fired after an in-app navigation to a setting's hash (see useSettingsAnchorHighlight). */
export const SETTINGS_ANCHOR_EVENT = 'openctem:settings-anchor'

/**
 * Ask the settings shell to scroll to and outline the element named by the
 * current URL hash: Next.js navigation changes the hash with pushState, which
 * fires no hashchange event.
 */
export function announceSettingsAnchor(): void {
  if (typeof window === 'undefined') return
  // After the navigation has updated the URL.
  window.setTimeout(() => window.dispatchEvent(new Event(SETTINGS_ANCHOR_EVENT)), 0)
}
