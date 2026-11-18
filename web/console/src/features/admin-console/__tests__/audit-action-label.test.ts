import { describe, it, expect } from 'vitest'
import { getDictionary, translate } from '@/lib/i18n'
import { auditActionLabel } from '../lib/audit-action-label'
import { roleName, platformRoleKey } from '../lib/role-name'
import { accountStatusLabel, authProviderLabel, memberRoleLabel } from '../lib/value-labels'
import { formatUtcTime } from '../lib/format-utc'

const tIn = (locale: 'en' | 'vi') => (key: string, fallback?: string) =>
  translate(getDictionary(locale), key, fallback)

describe('auditActionLabel', () => {
  it('reads the codes the console writes as translated labels', () => {
    expect(auditActionLabel(tIn('en'), 'console.elevated')).toBe('Elevated access started')
    expect(auditActionLabel(tIn('vi'), 'console.elevated')).toBe('Bắt đầu nâng quyền')
    expect(auditActionLabel(tIn('vi'), 'console.login')).toBe('Đăng nhập')
    expect(auditActionLabel(tIn('vi'), 'console.step_up')).toBe('Xác nhận lại danh tính')
    expect(auditActionLabel(tIn('en'), 'console.mfa_enrolled')).toBe(
      'Two-step verification enrolled'
    )
    expect(auditActionLabel(tIn('vi'), 'console.password_changed')).toBe('Đã đổi mật khẩu')
  })

  it('reads an unknown code as its words, never the raw code', () => {
    expect(auditActionLabel(tIn('en'), 'organization.idp_frobnicate')).toBe(
      'Identity provider frobnicate'
    )
  })

  it('has a Vietnamese label for every English one', () => {
    const en = getDictionary('en') as Record<string, string>
    const vi = getDictionary('vi') as Record<string, string>
    const keys = Object.keys(en).filter((k) => k.startsWith('admin.auditAction.'))
    expect(keys.length).toBeGreaterThan(100)
    for (const k of keys) expect(vi[k], k).toBeTruthy()
  })
})

describe('roleName: one name per role', () => {
  it('shows a base tier under the platform role it stands for', () => {
    expect(platformRoleKey('super_admin')).toBe('platform_owner')
    expect(roleName(tIn('en'), 'super_admin')).toBe('Platform owner')
    expect(roleName(tIn('en'), 'ops_admin')).toBe('Platform admin')
    expect(roleName(tIn('en'), 'readonly')).toBe('Read-only')
    expect(roleName(tIn('en'), 'platform_owner')).toBe('Platform owner')
    expect(roleName(tIn('vi'), 'super_admin')).toBe(roleName(tIn('vi'), 'platform_owner'))
  })
})

describe('value labels', () => {
  it('names how someone signs in once, in the language', () => {
    expect(authProviderLabel(tIn('en'), 'local')).toBe('Password')
    expect(authProviderLabel(tIn('vi'), 'local')).toBe('Mật khẩu')
    expect(authProviderLabel(tIn('en'), 'oidc')).toBe('Single sign-on')
    expect(authProviderLabel(tIn('en'), 'google')).toBe('Google')
    expect(authProviderLabel(tIn('en'), 'newidp')).toBe('Newidp')
  })

  it('translates member roles and statuses', () => {
    expect(memberRoleLabel(tIn('vi'), 'owner')).toBe('Chủ sở hữu')
    expect(accountStatusLabel(tIn('vi'), 'suspended')).toBe('Tạm ngưng')
  })
})

describe('formatUtcTime', () => {
  it('is the exact UTC time of the record', () => {
    expect(formatUtcTime('2026-11-18T03:54:09.512Z')).toBe('2026-11-18 03:54:09 UTC')
    expect(formatUtcTime(null)).toBe('')
    expect(formatUtcTime('nope')).toBe('')
  })
})
