import { describe, expect, it } from 'vitest'
import { FileText } from 'lucide-react'

import type { NavGroup } from '@/components/types'
import type { SettingsNavGroup } from '@/config/settings-nav'

import {
  assertCompatible,
  assertEditionName,
  mergeConsoleNav,
  mergeMessages,
  mergeNavGroups,
  mergeSettingsGroups,
} from '../merge'
import { EXTENSION_API_VERSION } from '../types'

const groups = (): NavGroup[] => [
  { title: 'Validation', items: [{ title: 'Pentests', url: '/pentests' }] },
]

describe('extension contract version', () => {
  it('accepts the version this core provides', () => {
    expect(() => assertCompatible('x', EXTENSION_API_VERSION)).not.toThrow()
  })
  it('refuses an overlay built for another version', () => {
    expect(() => assertCompatible('x', EXTENSION_API_VERSION + 1)).toThrow(/extension API/)
    expect(() => assertCompatible('x', EXTENSION_API_VERSION - 1)).toThrow(/extension API/)
  })
  it('validates the edition name', () => {
    expect(() => assertEditionName('enterprise')).not.toThrow()
    expect(() => assertEditionName('Bad Name')).toThrow()
    expect(() => assertEditionName('')).toThrow()
  })
})

describe('mergeNavGroups', () => {
  it('returns the core groups unchanged with nothing to add', () => {
    const g = groups()
    expect(mergeNavGroups(g, [])).toBe(g)
  })
  it('appends a row to the named group without mutating the core list', () => {
    const g = groups()
    const out = mergeNavGroups(g, [
      { group: 'Validation', item: { title: 'Extra', url: '/extra', module: 'extra' } },
    ])
    expect(out[0].items.map((i) => ('url' in i ? i.url : ''))).toEqual(['/pentests', '/extra'])
    expect(g[0].items).toHaveLength(1)
  })
  it('refuses an unknown group and a duplicate url', () => {
    expect(() =>
      mergeNavGroups(groups(), [{ group: 'Nope', item: { title: 'X', url: '/x' } }])
    ).toThrow(/does not exist/)
    expect(() =>
      mergeNavGroups(groups(), [{ group: 'Validation', item: { title: 'X', url: '/pentests' } }])
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
    const out = mergeSettingsGroups(settings(), [{ group: 'organization', item }])
    expect(out[0].items.map((i) => i.id)).toEqual(['general', 'extra'])
  })
  it('refuses an unknown group, a duplicate id and a duplicate url', () => {
    expect(() => mergeSettingsGroups(settings(), [{ group: 'nope', item }])).toThrow(
      /does not exist/
    )
    expect(() =>
      mergeSettingsGroups(settings(), [{ group: 'organization', item: { ...item, id: 'general' } }])
    ).toThrow(/already exists/)
    expect(() =>
      mergeSettingsGroups(settings(), [
        { group: 'organization', item: { ...item, url: '/settings/general' } },
      ])
    ).toThrow(/already exists/)
  })
})

describe('mergeConsoleNav', () => {
  const sections = () => [
    { i18nKey: 'admin.nav.group.security', items: [{ url: '/security/audit', title: 'Audit' }] },
  ]
  const row = { title: 'Extra', i18nKey: 'admin.nav.extra', url: '/security/extra', icon: FileText }

  it('appends a row to the section found by its key', () => {
    const out = mergeConsoleNav(sections(), [{ section: 'admin.nav.group.security', item: row }])
    expect(out[0].items.map((i) => i.url)).toEqual(['/security/audit', '/security/extra'])
  })
  it('refuses an unknown section and a duplicate url', () => {
    expect(() => mergeConsoleNav(sections(), [{ section: 'nope', item: row }])).toThrow(
      /does not exist/
    )
    expect(() =>
      mergeConsoleNav(sections(), [
        { section: 'admin.nav.group.security', item: { ...row, url: '/security/audit' } },
      ])
    ).toThrow(/already exists/)
  })
})

describe('mergeMessages', () => {
  it('adds new keys', () => {
    expect(mergeMessages({ 'a.b': 'A' }, { 'ee.x': 'X' })).toEqual({ 'a.b': 'A', 'ee.x': 'X' })
  })
  it('never lets an extension replace a core string', () => {
    expect(() => mergeMessages({ 'a.b': 'A' }, { 'a.b': 'changed' })).toThrow(/core key/)
  })
})
