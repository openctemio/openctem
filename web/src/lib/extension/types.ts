/**
 * The web extension API: what an extension build (a separately built
 * extension, a fork or any third-party build) can add to the tenant app and the console
 * (api/docs/development/editions.md). The default build resolves the
 * `@extension/*` modules to src/extension-default, which adds nothing; an
 * extension build resolves them to its own modules. An extension sees only
 * what is declared here, so anything it needs from the core is added to this
 * file first, in a core pull request, with a test. Names say what a point
 * does, never which build uses it.
 *
 * Bump EXTENSION_API_VERSION when a change here breaks an extension written
 * against the previous version (a removed or renamed member, a narrowed
 * type). Adding an optional member is not a break.
 */
import type { ComponentType } from 'react'
import type { LucideIcon } from 'lucide-react'

import type { NavItem } from '@/components/types'
import type { SettingsNavItem } from '@/config/settings-nav'

/** Version of this contract. The extension states the version it was built for. */
export const EXTENSION_API_VERSION = 1

/** A sidebar row the extension adds to an existing tenant-app group. */
export interface ExtensionNavItem {
  /** English title of the group the row joins (as in config/sidebar-data.ts). */
  group: string
  /**
   * Grant key that must be on for the organization, or the row is not shown.
   * Hiding is a convenience: the API route behind the page enforces
   * permission and grant on its own.
   */
  grant: string
  /** The row. Its `module` and `permission` gate it like any core row. */
  item: NavItem
}

/** A settings page the extension adds to an existing settings group. */
export interface ExtensionSettingsItem {
  /** Id of the settings group (config/settings-nav.ts), e.g. `organization`. */
  group: string
  /** Grant key that must be on for the organization, or the page is not listed. */
  grant: string
  item: SettingsNavItem
}

/**
 * Named places in core pages where the extension may render. A core page
 * renders `<ExtensionSlot id="..." />`; the key's value is the props the
 * page passes. New slots are added here by the core pull request that adds
 * the `<ExtensionSlot>` to the page.
 */
export interface ExtensionSlotProps {
  /** Extra sections on the Reports page, below the core sections. */
  'reports.sections': NoProps
  /** Extra sections on the SCIM settings page, below the token list. */
  'settings.scim.sections': NoProps
}

/** Props of a slot that receives none. */
export type NoProps = Record<never, never>

export type ExtensionSlotId = keyof ExtensionSlotProps

/**
 * The short list of core components an extension may replace as a whole,
 * each with a stable props contract. Everything else is extended through
 * slots: core pages are never copied or forked. A core page renders
 * `<Overridable id="..." fallback={CoreComponent} />`. Look and feel is
 * changed through design tokens and brand settings, never by replacing a
 * component for its styling.
 */
export interface ExtensionOverrideProps {
  /** Below the card of the sign-in and other unauthenticated pages. */
  'auth.footer': { className?: string }
}

export type ExtensionOverrideId = keyof ExtensionOverrideProps

/** What the extension's `@extension/web` module exports as `extension`. */
export interface WebExtension {
  /** The EXTENSION_API_VERSION the extension was built for. */
  apiVersion: number
  /** Name of the extension: lower-case letters, digits and dashes. */
  name: string
  navItems: readonly ExtensionNavItem[]
  settingsItems: readonly ExtensionSettingsItem[]
  slots: { readonly [K in ExtensionSlotId]?: ComponentType<ExtensionSlotProps[K]> }
  overrides: { readonly [K in ExtensionOverrideId]?: ComponentType<ExtensionOverrideProps[K]> }
}

/** A console sidebar row (same fields as the console's own rows). */
export interface ExtensionConsoleNavItem {
  /** i18nKey of the console section the row joins, e.g. `admin.nav.group.security`. */
  section: string
  /** Grant key that must be on for the installation, or the row is not shown. */
  grant: string
  item: {
    title: string
    i18nKey: string
    url: string
    icon: LucideIcon
    permission?: string
    keywords?: string[]
  }
}

/** What the extension's `@extension/console` module exports as `extension`. */
export interface ConsoleExtension {
  apiVersion: number
  navItems: readonly ExtensionConsoleNavItem[]
}

/**
 * What the extension's `@extension/messages` module exports: extra catalog entries
 * per locale. They may add keys, never replace a core key.
 */
export interface ExtensionMessages {
  apiVersion: number
  en: Readonly<Record<string, string>>
  vi: Readonly<Record<string, string>>
}
