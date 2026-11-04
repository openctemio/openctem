/**
 * Pure functions that fold an extension's registrations into the core's
 * navigation and catalogs. They run once at module load. Every mismatch
 * throws: an extension that does not fit the core must fail its build and its
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

/**
 * Answers whether a grant key is on for the organization (tenant app) or the
 * installation (console). The web only hides what a grant does not cover: the
 * API route behind every extension page checks permission and grant itself,
 * so a wrong answer here can show a row that then answers 403, never open data.
 */
export type GrantCheck = (grant: string) => boolean

const NAME_RE = /^[a-z][a-z0-9-]{0,31}$/

/** Refuses an extension built for another contract version. */
export function assertCompatible(what: string, apiVersion: number): void {
  if (apiVersion !== EXTENSION_API_VERSION) {
    throw new Error(
      `${what}: built for extension API ${apiVersion}, this core provides ${EXTENSION_API_VERSION}`
    )
  }
}

export function assertExtensionName(name: string): void {
  if (!NAME_RE.test(name)) throw new Error(`extension: invalid name "${name}"`)
}

/** Appends extension rows whose grant is on to the named sidebar groups. */
export function mergeNavGroups(
  groups: NavGroup[],
  extra: readonly ExtensionNavItem[],
  isGrantOn: GrantCheck
): NavGroup[] {
  const rows = extra.filter((r) => isGrantOn(r.grant))
  if (rows.length === 0) return groups
  const out = groups.map((g) => ({ ...g, items: [...g.items] }))
  const urls = new Set(out.flatMap((g) => g.items.map((i) => ('url' in i ? String(i.url) : ''))))
  for (const { group, item } of rows) {
    const target = out.find((g) => g.title === group)
    if (!target) throw new Error(`extension: sidebar group "${group}" does not exist`)
    if ('url' in item && urls.has(String(item.url))) {
      throw new Error(`extension: sidebar row ${String(item.url)} already exists`)
    }
    target.items.push(item)
  }
  return out
}

/** Appends extension pages whose grant is on to the named settings groups. */
export function mergeSettingsGroups(
  groups: SettingsNavGroup[],
  extra: readonly ExtensionSettingsItem[],
  isGrantOn: GrantCheck
): SettingsNavGroup[] {
  const rows = extra.filter((r) => isGrantOn(r.grant))
  if (rows.length === 0) return groups
  const out = groups.map((g) => ({ ...g, items: [...g.items] }))
  const ids = new Set(out.flatMap((g) => g.items.map((i) => i.id)))
  const urls = new Set(out.flatMap((g) => g.items.map((i) => i.url)))
  for (const { group, item } of rows) {
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

/** Appends extension rows whose grant is on to the console sections, found by their i18nKey. */
export function mergeConsoleNav<
  S extends { i18nKey?: string; items: I[] },
  I extends { url: string },
>(sections: S[], extra: readonly ExtensionConsoleNavItem[], isGrantOn: GrantCheck): S[] {
  const rows = extra.filter((r) => isGrantOn(r.grant))
  if (rows.length === 0) return sections
  const out = sections.map((s) => ({ ...s, items: [...s.items] }))
  const urls = new Set(out.flatMap((s) => s.items.map((i) => i.url)))
  for (const { section, item } of rows) {
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
