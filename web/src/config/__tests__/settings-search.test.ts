import { describe, expect, it } from 'vitest'
import { Shield } from 'lucide-react'
import {
  anchorHref,
  foldSearchText,
  matchesAllWords,
  searchSettings,
  type SearchableItem,
} from '../settings-search'

const items: SearchableItem[] = [
  {
    id: 'authentication',
    title: 'Authentication',
    url: '/settings/authentication',
    keywords: ['2fa', 'sign-in'],
    icon: Shield,
    label: 'Xác thực',
    desc: 'Xác thực hai lớp, danh sách IP được phép',
    groupLabel: 'Bảo mật',
    groupTitle: 'Security',
    searchAnchors: [
      {
        id: 'ip-allowlist',
        title: 'IP allowlist',
        label: 'Danh sách IP được phép',
        keywords: ['cidr'],
      },
      {
        id: 'two-factor',
        title: 'Require two-factor authentication',
        label: 'Bắt buộc xác thực hai lớp',
      },
    ],
  },
  {
    id: 'members',
    title: 'Members',
    url: '/settings/members',
    icon: Shield,
    label: 'Members',
    desc: 'People in the organization',
    groupLabel: 'Access',
    groupTitle: 'Access',
    searchAnchors: [],
  },
]

describe('settings search', () => {
  it('folds case, accents and đ', () => {
    expect(foldSearchText('Đăng Nhập')).toBe('dang nhap')
    expect(matchesAllWords('xac thuc', ['Xác thực hai lớp'])).toBe(true)
  })

  it('an empty query finds nothing (the page shows the groups instead)', () => {
    expect(searchSettings(items, '   ')).toEqual([])
  })

  it('finds a setting inside a page and links to its anchor', () => {
    const r = searchSettings(items, 'cidr')
    expect(r).toHaveLength(1)
    expect(r[0]).toMatchObject({
      key: 'authentication#ip-allowlist',
      anchorId: 'ip-allowlist',
      href: '/settings/authentication#ip-allowlist',
      context: 'Bảo mật › Xác thực',
    })
  })

  it('matches the English title of a setting in another language too', () => {
    expect(searchSettings(items, 'ip allowlist').map((r) => r.key)).toEqual([
      'authentication#ip-allowlist',
    ])
  })

  it("matches a page on its own words without listing the page's settings", () => {
    expect(searchSettings(items, 'sign-in').map((r) => r.key)).toEqual(['authentication'])
    expect(searchSettings(items, 'bao mat').map((r) => r.key)).toEqual(['authentication'])
  })

  it('lists the page, then its matching settings, in rail order', () => {
    expect(searchSettings(items, '2fa').map((r) => r.key)).toEqual(['authentication'])
    expect(searchSettings(items, 'hai lop').map((r) => r.key)).toEqual([
      'authentication',
      'authentication#two-factor',
    ])
  })

  it('builds anchor URLs', () => {
    expect(anchorHref('/settings/x', 'y')).toBe('/settings/x#y')
  })
})
