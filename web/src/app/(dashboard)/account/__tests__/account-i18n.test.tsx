import { describe, it, expect, vi } from 'vitest'

// The hooks below return the same object on every render, like the real SWR
// hooks do. The pages copy them into state in an effect keyed on the object, so a
// fresh literal per call would re-render forever and run the worker out of memory.
const h = vi.hoisted(() => ({
  profile: {
    id: 'user-1234',
    email: 'a@b.co',
    name: 'An',
    email_verified: true,
    auth_provider: 'local',
  },
  preferences: { theme: 'system', language: 'en' },
  notificationPrefs: {
    in_app_enabled: true,
    muted_types: [] as string[],
    min_severity: 'info',
    auto_watch: true,
  },
  activities: [] as unknown[],
}))
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import ProfilePage from '../page'
import PreferencesPage from '../preferences/page'
import ActivityPage from '../activity/page'
import NotificationsPage from '../notifications/page'
import { PasswordCard } from '@/features/account/components/password-card'
import { SessionsCard } from '@/features/account/components/sessions-card'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))
vi.mock('next-themes', () => ({ useTheme: () => ({ theme: 'system', setTheme: vi.fn() }) }))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u1' }) }))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({ page: 1, setPage: vi.fn() }),
}))
vi.mock('@/features/organization/components/leave-organization', () => ({
  LeaveOrganization: () => null,
}))
vi.mock('@/features/auth/api/use-auth-providers', () => ({ usePasswordPolicy: () => undefined }))
vi.mock('@/features/auth/components/password-policy-hint', () => ({
  PasswordPolicyHint: () => null,
}))
vi.mock('@/features/notifications/api/use-notification-api', () => ({
  useNotificationPreferencesApi: () => ({
    data: h.notificationPrefs,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  updateNotificationPreferences: vi.fn(),
  invalidatePreferencesCache: vi.fn(),
}))
vi.mock('@/features/account', async (orig) => ({
  ...(await orig<object>()),
  useProfile: () => ({
    profile: h.profile,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useUpdateProfile: () => ({ updateProfile: vi.fn(), isUpdating: false }),
  usePreferences: () => ({
    preferences: h.preferences,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useUpdatePreferences: () => ({ updatePreferences: vi.fn(), isUpdating: false }),
  useAccountActivity: () => ({ activities: h.activities, total: 0, totalPages: 0, isLoading: false }),
}))

const inVi = (ui: React.ReactElement) => render(<I18nProvider locale="vi">{ui}</I18nProvider>)

describe('account pages in Vietnamese', () => {
  it('profile page', () => {
    inVi(<ProfilePage />)
    expect(screen.getByText('Thông tin hồ sơ')).toBeInTheDocument()
    expect(screen.getByLabelText('Họ và tên')).toBeInTheDocument()
    expect(screen.getByText('Lưu thay đổi')).toBeInTheDocument()
    expect(screen.queryByText('Save Changes')).not.toBeInTheDocument()
    // The user id stays visible, labelled and in mono.
    const id = screen.getByText('user-1234')
    expect(id).toHaveClass('font-mono')
    expect(screen.getByText('ID người dùng')).toBeInTheDocument()
  })

  it('preferences page', () => {
    inVi(<PreferencesPage />)
    expect(screen.getByText('Giao diện')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sáng' })).toBeInTheDocument()
    expect(screen.getByText('Tự động chuyển theo cài đặt hệ thống của bạn')).toBeInTheDocument()
    expect(screen.queryByText('Automatically switch based on your system settings')).toBeNull()
  })

  it('activity page', () => {
    inVi(<ActivityPage />)
    expect(screen.getByText('Nhật ký hoạt động')).toBeInTheDocument()
    expect(screen.getByText('Không có hoạt động nào')).toBeInTheDocument()
    expect(screen.queryByText('No activity found')).toBeNull()
  })

  it('notifications page', () => {
    inVi(<NotificationsPage />)
    expect(screen.getByText('Thông báo trong ứng dụng')).toBeInTheDocument()
    expect(screen.getByText('Bộ lọc mức độ nghiêm trọng')).toBeInTheDocument()
    expect(screen.queryByText('Severity filter')).toBeNull()
  })

  it('password and sessions cards', () => {
    inVi(
      <>
        <PasswordCard isLocalAccount />
        <SessionsCard sessions={[]} isLoading={false} onChanged={vi.fn()} />
      </>
    )
    expect(
      screen.getByText('Đổi mật khẩu sẽ đăng xuất mọi phiên đăng nhập khác.')
    ).toBeInTheDocument()
    expect(
      screen.getByText('Các thiết bị đang đăng nhập vào tài khoản của bạn.')
    ).toBeInTheDocument()
    expect(screen.getByText('Không có phiên đang hoạt động')).toBeInTheDocument()
    expect(screen.queryByText('Devices signed in to your account.')).toBeNull()
  })
})
