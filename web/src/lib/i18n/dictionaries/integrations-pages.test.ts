import { describe, expect, it } from 'vitest'
import { getDictionary, translate } from '@/lib/i18n'

// The notification-channel pages and the SCM connections page resolve their
// text through these keys in both shipped catalogs.
const KEYS: Record<string, [string, string]> = {
  'notificationChannels.page.title': ['Notification channels', 'Kênh thông báo'],
  'notificationChannels.history.title': ['Notification events', 'Sự kiện thông báo'],
  'notificationChannels.outbox.title': ['Notification queue', 'Hàng đợi thông báo'],
  'notificationChannels.status.error': ['Error', 'Lỗi'],
  'notificationChannels.outbox.status.dead': ['Dead', 'Đã bỏ'],
  'scmIntegration.page.title': ['SCM connections', 'Kết nối SCM'],
  'scmIntegration.col.lastVerified': ['Last verified', 'Xác minh lần cuối'],
}

describe('integrations pages catalogs', () => {
  for (const [key, [en, vi]] of Object.entries(KEYS)) {
    it(`${key} resolves in en and vi`, () => {
      expect(translate(getDictionary('en'), key, 'fallback')).toBe(en)
      expect(translate(getDictionary('vi'), key, 'fallback')).toBe(vi)
    })
  }

  it('interpolates counts and names', () => {
    const vi = getDictionary('vi')
    expect(translate(vi, 'scmIntegration.repoCount', 'x', { count: 3 })).toBe('3 kho')
    expect(translate(vi, 'notificationChannels.toast.rateLimited', 'x', { seconds: 30 })).toContain(
      '30 giây'
    )
  })
})
