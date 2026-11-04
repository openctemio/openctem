import { describe, expect, it } from 'vitest'
import { FileText } from 'lucide-react'

import type { NavGroup } from '@/components/types'
import type { SettingsNavGroup } from '@/config/settings-nav'

import {
  assertCompatible,
  assertExtensionName,
  mergeConsoleNav,
  mergeMessages,
  mergeNavGroups,
  mergeSettingsGroups,
} from '../merge'
import { EXTENSION_API_VERSION } from '../types'

const on = () => true
const off = () => false

const groups = (): NavGroup[] => [
  { title: 'Validation', items: [{ title: 'Pentests', url: '/pentests' }] },
]

describe('extension contract version', () => {
  it('accepts the version this core provides', () => {
    expect(() => assertCompatible('x', EXTENSION_API_VERSION)).not.toThrow()
  })
  it('refuses an extension built for another version', () => {
    expect(() => assertCompatible('x', EXTENSION_API_VERSION + 1)).toThrow(/extension API/)
    expect(() => assertCompatible('x', EXTENSION_API_VERSION - 1)).toThrow(/extension API/)
  })
  it('validates the extension name', () => {
    expect(() => assertExtensionName('acme-ext')).not.toThrow()
    expect(() => assertExtensionName('Bad Name')).toThrow()
    expect(() => assertExtensionName('')).toThrow()
  })
})

describe('mergeNavGroups', () => {
  it('returns the core groups unchanged with nothing to add', () => {
    const g = groups()
    expect(mergeNavGroups(g, [], on)).toBe(g)
  })
  it('appends a row to the named group without mutating the core list', () => {
    const g = groups()
    const out = mergeNavGroups(
      g,
      [
        {
          group: 'Validation',
          grant: 'g',
          item: { title: 'Extra', url: '/extra', module: 'extra' },
        },
      ],
      on
    )
    expect(out[0].items.map((i) => ('url' in i ? i.url : ''))).toEqual(['/pentests', '/extra'])
    expect(g[0].items).toHaveLength(1)
  })
  it('keeps a row only when its grant is on', () => {
    const rows = [
      { group: 'Validation', grant: 'on_grant', item: { title: 'A', url: '/a' } },
      { group: 'Validation', grant: 'off_grant', item: { title: 'B', url: '/b' } },
    ]
    const out = mergeNavGroups(groups(), rows, (g) => g === 'on_grant')
    expect(out[0].items.map((i) => ('url' in i ? i.url : ''))).toEqual(['/pentests', '/a'])
    const g = groups()
    expect(mergeNavGroups(g, rows, off)).toBe(g)
  })
  it('refuses an unknown group and a duplicate url', () => {
    expect(() =>
      mergeNavGroups(groups(), [{ group: 'Nope', grant: 'g', item: { title: 'X', url: '/x' } }], on)
    ).toThrow(/does not exist/)
    expect(() =>
      mergeNavGroups(
        groups(),
        [{ group: 'Validation', grant: 'g', item: { title: 'X', url: '/pentests' } }],
        on
      )
    ).toThrow(/already exists/)
  })
})

describe('mergeSettingsGroups', () => {
  const settings = (): SettingsNavGroup[] => [
    {
      id: 'organization',
      title: 'Organization',
      items: [
        {
          id: 'general',
          title: 'General',
          description: 'd',
          url: '/settings/general',
          icon: FileText,
        },
      ],
    },
  ]
  const item = {
    id: 'extra',
    title: 'Extra',
    description: 'd',
    url: '/settings/extra',
    icon: FileText,
    permission: 'x:read',
  }

  it('appends a page to the named group', () => {
    const out = mergeSettingsGroups(settings(), [{ group: 'organization', grant: 'g', item }], on)
    expect(out[0].items.map((i) => i.id)).toEqual(['general', 'extra'])
  })
  it('lists a page only when its grant is on', () => {
    const s = settings()
    expect(mergeSettingsGroups(s, [{ group: 'organization', grant: 'g', item }], off)).toBe(s)
  })
  it('refuses an unknown group, a duplicate id and a duplicate url', () => {
    expect(() =>
      mergeSettingsGroups(settings(), [{ group: 'nope', grant: 'g', item }], on)
    ).toThrow(/does not exist/)
    expect(() =>
      mergeSettingsGroups(
        settings(),
        [{ group: 'organization', grant: 'g', item: { ...item, id: 'general' } }],
        on
      )
    ).toThrow(/already exists/)
    expect(() =>
      mergeSettingsGroups(
        settings(),
        [{ group: 'organization', grant: 'g', item: { ...item, url: '/settings/general' } }],
        on
      )
    ).toThrow(/already exists/)
  })
})

describe('mergeConsoleNav', () => {
  const sections = () => [
    { i18nKey: 'admin.nav.group.security', items: [{ url: '/security/audit', title: 'Audit' }] },
  ]
  const row = { title: 'Extra', i18nKey: 'admin.nav.extra', url: '/security/extra', icon: FileText }

  it('appends a row to the section found by its key', () => {
    const out = mergeConsoleNav(
      sections(),
      [{ section: 'admin.nav.group.security', grant: 'g', item: row }],
      on
    )
    expect(out[0].items.map((i) => i.url)).toEqual(['/security/audit', '/security/extra'])
  })
  it('shows a row only when its grant is on', () => {
    const s = sections()
    expect(
      mergeConsoleNav(s, [{ section: 'admin.nav.group.security', grant: 'g', item: row }], off)
    ).toBe(s)
  })
  it('refuses an unknown section and a duplicate url', () => {
    expect(() =>
      mergeConsoleNav(sections(), [{ section: 'nope', grant: 'g', item: row }], on)
    ).toThrow(/does not exist/)
    expect(() =>
      mergeConsoleNav(
        sections(),
        [
          {
            section: 'admin.nav.group.security',
            grant: 'g',
            item: { ...row, url: '/security/audit' },
          },
        ],
        on
      )
    ).toThrow(/already exists/)
  })
})

describe('mergeMessages', () => {
  it('adds new keys', () => {
    expect(mergeMessages({ 'a.b': 'A' }, { 'acme.x': 'X' })).toEqual({ 'a.b': 'A', 'acme.x': 'X' })
  })
  it('never lets an extension replace a core string', () => {
    expect(() => mergeMessages({ 'a.b': 'A' }, { 'a.b': 'changed' })).toThrow(/core key/)
  })
})
