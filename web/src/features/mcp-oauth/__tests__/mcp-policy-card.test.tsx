/**
 * The organization's AI policy card: the TLP limit for AI applications is
 * shown with the policy and sent back on save, in English and Vietnamese.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

const update = vi.fn()
const policy = {
  enabled: true,
  any_client: false,
  client_hosts: [],
  scopes: [],
  api_keys_allowed: true,
  refresh_days: 0,
  effective_refresh_days: 90,
  require_dpop: false,
  max_tlp: 'green',
  platform_client_hosts: [],
  available_scopes: [{ scope: 'mcp:pentest.read', title: 'Read pentest campaigns', write: false }],
}

vi.mock('../api/connections', () => ({
  useMcpPolicy: () => ({ data: policy, isLoading: false, error: undefined }),
  updateMcpPolicy: (p: unknown) => update(p),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { McpPolicyCard } from '../components/mcp-policy-card'

describe('MCP policy card', () => {
  beforeEach(() => update.mockReset().mockResolvedValue(policy))

  it('shows the TLP limit and sends it on save', async () => {
    render(
      <I18nProvider locale="en">
        <McpPolicyCard canEdit />
      </I18nProvider>
    )
    expect(screen.getByText('Highest TLP sent to AI applications')).toBeTruthy()
    expect(screen.getByRole('combobox').textContent).toContain('TLP:GREEN')
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith(expect.objectContaining({ max_tlp: 'green' }))
    )
  })

  it('is translated', () => {
    render(
      <I18nProvider locale="vi">
        <McpPolicyCard canEdit={false} />
      </I18nProvider>
    )
    expect(screen.getByText('Mức TLP cao nhất gửi cho ứng dụng AI')).toBeTruthy()
    expect(screen.getByText('Chính sách của tổ chức')).toBeTruthy()
  })
})
