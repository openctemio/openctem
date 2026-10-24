/**
 * The vulnerability matching form and the "Why this finding" panel render
 * Vietnamese, and the muted-products field has a label.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { I18nProvider } from '@/context/i18n-provider'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), put: vi.fn() }))

import { VulnMatchingSettingsForm } from '../components/vuln-matching-settings-form'
import { VersionMatchPanel } from '../components/version-match-panel'
import { validateVulnMatching } from '../types'

const wrap = (ui: React.ReactNode) =>
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <I18nProvider locale="vi">{ui}</I18nProvider>
    </SWRConfig>
  )

describe('vulnerability matching (vi)', () => {
  it('translates the form and labels the muted products field', () => {
    wrap(<VulnMatchingSettingsForm initial={{ enabled: false }} formId="f" />)
    expect(screen.getByText('Đối chiếu')).toBeInTheDocument()
    expect(screen.getByLabelText('Tạo phát hiện từ kết quả khớp phiên bản')).toBeInTheDocument()
    expect(screen.getByLabelText('Độ tin cậy tối thiểu')).toBeInTheDocument()
    expect(screen.getByLabelText('Sản phẩm tắt tiếng')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Tên sản phẩm, ví dụ OpenSSH')).toBeInTheDocument()
    expect(screen.queryByText('Minimum confidence')).not.toBeInTheDocument()
    expect(screen.queryByText('Muted products')).not.toBeInTheDocument()
  })

  it('translates the panel', () => {
    wrap(
      <VersionMatchPanel
        metadata={{
          version_match: {
            label: 'potential',
            confidence: 35,
            product: 'OpenSSH',
            version: '8.2p1',
            source: 'nvd',
          },
        }}
      />
    )
    expect(screen.getByText('Vì sao có phát hiện này')).toBeInTheDocument()
    expect(screen.getByText('Dải bị ảnh hưởng')).toBeInTheDocument()
    expect(screen.getByText('Nguồn: NVD')).toBeInTheDocument()
    expect(screen.queryByText('Why this finding')).not.toBeInTheDocument()
  })

  it('validates in the given language', () => {
    const vi_ = (key: string, fb = '') => (key.endsWith('errConfidence') ? 'sai' : fb)
    expect(validateVulnMatching({ min_confidence: 101 }, vi_)).toBe('sai')
  })
})
