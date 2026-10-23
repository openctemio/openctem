/**
 * The sign-in and registration pages follow the user's language, the card
 * title is the page heading, and the password toggle names its action.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { I18nProvider } from '@/context/i18n-provider'
import { PasswordInput } from '@/components/password-input'
import { useAuthProviders } from '../../api/use-auth-providers'
import { RegisterGate } from '../register-gate'
import { RegisterForm } from '../register-form'
import { LoginHeader } from '../login-header'
import { LegalNotice } from '../legal-notice'

vi.mock('../../api/use-auth-providers')
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('../../actions/local-auth-actions', () => ({ registerAction: vi.fn() }))
vi.mock('../../actions/social-auth-actions', () => ({ initiateSocialLogin: vi.fn() }))

function providers() {
  vi.mocked(useAuthProviders).mockReturnValue({
    data: { social: {}, registration_enabled: true },
    isLoading: false,
  } as unknown as ReturnType<typeof useAuthProviders>)
}

const vi_ = (ui: React.ReactNode) => render(<I18nProvider locale="vi">{ui}</I18nProvider>)

describe('auth pages in Vietnamese', () => {
  it('login header is the h1', () => {
    providers()
    vi_(<LoginHeader />)
    expect(screen.getByRole('heading', { level: 1, name: 'Đăng nhập' })).toBeInTheDocument()
    expect(screen.queryByText('Sign in')).toBeNull()
  })

  it('register page: heading, labels and validation messages', async () => {
    providers()
    vi_(<RegisterGate />)
    expect(screen.getByRole('heading', { level: 1, name: 'Tạo tài khoản' })).toBeInTheDocument()
    expect(screen.getByText('Tên')).toBeInTheDocument()
    expect(screen.getByText('Xác nhận mật khẩu')).toBeInTheDocument()
    expect(screen.queryByText('First Name')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /Tạo tài khoản/ }))
    await waitFor(() => expect(screen.getByText('Nhập tên của bạn')).toBeInTheDocument())
    expect(screen.queryByText('Please enter your first name')).toBeNull()
  })

  it('register form keeps English validation by default', async () => {
    providers()
    render(<RegisterForm />)
    await userEvent.click(screen.getByRole('button', { name: /Create account/ }))
    await waitFor(() => expect(screen.getByText('Enter your first name')).toBeInTheDocument())
  })

  it('legal notice', () => {
    vi_(<LegalNotice kind="signIn" termsUrl="https://e.x/t" privacyUrl="https://e.x/p" />)
    expect(screen.getByRole('link', { name: 'Điều khoản dịch vụ' })).toHaveAttribute(
      'href',
      'https://e.x/t'
    )
    expect(screen.getByText(/Khi chọn đăng nhập/)).toBeInTheDocument()
  })

  it('password toggle names its action and shows the eye while hidden', async () => {
    const { container } = vi_(<PasswordInput />)
    const toggle = screen.getByRole('button', { name: 'Hiện mật khẩu' })
    expect(container.querySelector('svg.lucide-eye')).not.toBeNull()
    await userEvent.click(toggle)
    expect(screen.getByRole('button', { name: 'Ẩn mật khẩu' })).toBeInTheDocument()
    expect(container.querySelector('svg.lucide-eye-off')).not.toBeNull()
  })
})
