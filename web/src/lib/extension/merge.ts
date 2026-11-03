/**
 * Pure functions that fold an extension's registrations into the core's
 * navigation and catalogs. They run once at module load. Every mismatch
 * throws: an overlay that does not fit the core must fail its build and its
 * tests, never ship a page that silently lacks (or replaces) something.
 */
import type { NavGroup } from '@/components/types'
import type { SettingsNavGroup } from '@/config/settings-nav'

import {
  EXTENSION_API_VERSION,
  type ExtensionConsoleNavItem,
  type ExtensionNavItem,
  type ExtensionSettingsItem,
} from './types'

const EDITION_RE = /^[a-z][a-z0-9-]{0,31}$/

/** Refuses an overlay built for another contract version. */
export function assertCompatible(what: string, apiVersion: number): void {
  if (apiVersion !== EXTENSION_API_VERSION) {
    throw new Error(
      `${what}: built for extension API ${apiVersion}, this core provides ${EXTENSION_API_VERSION}`
    )
  }
}

export function assertEditionName(edition: string): void {
  if (!EDITION_RE.test(edition)) throw new Error(`extension: invalid edition name "${edition}"`)
}

/** Appends extension rows to the named sidebar groups. */
export function mergeNavGroups(groups: NavGroup[], extra: readonly ExtensionNavItem[]): NavGroup[] {
  if (extra.length === 0) return groups
  const out = groups.map((g) => ({ ...g, items: [...g.items] }))
  const urls = new Set(out.flatMap((g) => g.items.map((i) => ('url' in i ? String(i.url) : ''))))
  for (const { group, item } of extra) {
    const target = out.find((g) => g.title === group)
    if (!target) throw new Error(`extension: sidebar group "${group}" does not exist`)
    if ('url' in item && urls.has(String(item.url))) {
      throw new Error(`extension: sidebar row ${String(item.url)} already exists`)
    }
    target.items.push(item)
  }
  return out
}

/** Appends extension pages to the named settings groups. */
export function mergeSettingsGroups(
  groups: SettingsNavGroup[],
  extra: readonly ExtensionSettingsItem[]
): SettingsNavGroup[] {
  if (extra.length === 0) return groups
  const out = groups.map((g) => ({ ...g, items: [...g.items] }))
  const ids = new Set(out.flatMap((g) => g.items.map((i) => i.id)))
  const urls = new Set(out.flatMap((g) => g.items.map((i) => i.url)))
  for (const { group, item } of extra) {
    const target = out.find((g) => g.id === group)
    if (!target) throw new Error(`extension: settings group "${group}" does not exist`)
    if (ids.has(item.id) || urls.has(item.url)) {
      throw new Error(`extension: settings page ${item.id} (${item.url}) already exists`)
    }
    ids.add(item.id)
    urls.add(item.url)
    target.items.push(item)
  }
  return out
}

/** Appends extension rows to the console sections, found by their i18nKey. */
export function mergeConsoleNav<
  S extends { i18nKey?: string; items: I[] },
  I extends { url: string },
>(sections: S[], extra: readonly ExtensionConsoleNavItem[]): S[] {
  if (extra.length === 0) return sections
  const out = sections.map((s) => ({ ...s, items: [...s.items] }))
  const urls = new Set(out.flatMap((s) => s.items.map((i) => i.url)))
  for (const { section, item } of extra) {
    const target = out.find((s) => s.i18nKey === section)
    if (!target) throw new Error(`extension: console section "${section}" does not exist`)
    if (urls.has(item.url)) throw new Error(`extension: console row ${item.url} already exists`)
    urls.add(item.url)
    target.items.push(item as unknown as I)
  }
  return out
}

/** Adds extension catalog entries; replacing a core entry is refused. */
export function mergeMessages(
  core: Record<string, string>,
  extra: Readonly<Record<string, string>>
): Record<string, string> {
  const keys = Object.keys(extra)
  if (keys.length === 0) return core
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(core, k)) {
      throw new Error(`extension: catalog key "${k}" is a core key and cannot be replaced`)
    }
  }
  return { ...core, ...extra }
}
