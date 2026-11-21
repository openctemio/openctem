import { describe, expect, it } from 'vitest'
import { roleDisplayDescription, roleDisplayName } from '../system-role'

const vi: Record<string, string> = {
  'org.systemRole.owner': 'Chủ sở hữu',
  'org.systemRoleDescription.owner': 'Toàn quyền với mọi thứ, kể cả quản lý nhóm',
}
const t = (key: string, fallback: string) => vi[key] ?? fallback

describe('system role text', () => {
  it('names and describes a built-in role in the console language', () => {
    const owner = { slug: 'owner', name: 'Owner', description: 'Full access', is_system: true }
    expect(roleDisplayName(t, owner)).toBe('Chủ sở hữu')
    expect(roleDisplayDescription(t, owner)).toBe('Toàn quyền với mọi thứ, kể cả quản lý nhóm')
  })

  it('keeps a custom role as its author wrote it, even with a built-in slug', () => {
    const custom = { slug: 'owner', name: 'Kiểm toán viên', description: '', is_system: false }
    expect(roleDisplayName(t, custom)).toBe('Kiểm toán viên')
    expect(roleDisplayDescription(t, custom)).toBeUndefined()
  })
})
