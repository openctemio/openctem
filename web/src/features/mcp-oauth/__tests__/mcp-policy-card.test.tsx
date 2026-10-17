/**
 * The organization's AI policy: the TLP limit is shown and sent back on
 * save, the comment-adding write scope can be allowed, which applications
 * may connect is not part of this form, and it is translated.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

import type { McpPolicy } from '../api/connections'

const patch = vi.fn()
const policy: McpPolicy = {
  enabled: true,
  any_client: false,
  client_hosts: ['assistant.example'],
  scopes: [],
  api_keys_allowed: true,
  refresh_days: 0,
  effective_refresh_days: 90,
  require_dpop: false,
  max_tlp: 'green',
  platform_client_hosts: [],
  available_scopes: [
    { scope: 'mcp:findings.read', title: 'Read findings', write: false },
    { scope: 'mcp:pentest.read', title: 'Read pentest campaigns', write: false },
    { scope: 'mcp:findings.comment', title: 'Add comments', write: true },
  ],
}

vi.mock('../api/connections', () => ({
  patchMcpPolicy: (current: unknown, p: unknown) => patch(current, p),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { McpPolicyCard } from '../components/mcp-policy-card'

const renderCard = (locale = 'en', canEdit = true) =>
  render(
    <I18nProvider locale={locale}>
      <McpPolicyCard policy={policy} canEdit={canEdit} />
    </I18nProvider>
  )

describe('MCP policy card', () => {
  beforeEach(() => patch.mockReset().mockResolvedValue(policy))

  it('shows the TLP limit and sends it on save without touching the applications', async () => {
    renderCard()
    expect(screen.getByText('Highest TLP sent to AI applications')).toBeTruthy()
    expect(screen.getByRole('combobox').textContent).toContain('TLP:GREEN')
    expect(screen.queryByText('Allow unverified applications')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(patch).toHaveBeenCalled())
    const sent = patch.mock.calls[0][1] as Record<string, unknown>
    expect(sent.max_tlp).toBe('green')
    expect(sent).not.toHaveProperty('any_client')
    expect(sent).not.toHaveProperty('client_hosts')
  })

  it('offers the comment scope, off by default, and sends it when allowed', async () => {
    renderCard()
    const comment = screen.getByRole('checkbox', {
      name: /Add comments to findings, each one confirmed by you/,
    })
    expect(comment).not.toBeChecked()
    fireEvent.click(comment)
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect((patch.mock.calls[0][1] as { scopes: string[] }).scopes).toEqual([
      'mcp:findings.comment',
      'mcp:findings.read',
      'mcp:pentest.read',
    ])
  })

  it('needs at least one read scope', () => {
    renderCard()
    for (const name of [/Read findings, vulnerabilities/, /Read pentest campaigns/]) {
      fireEvent.click(screen.getByRole('checkbox', { name }))
    }
    expect(screen.getByRole('alert').textContent).toContain('at least one')
    expect(screen.getByRole('button', { name: 'Save policy' })).toBeDisabled()
  })

  it('is translated', () => {
    renderCard('vi', false)
    expect(screen.getByText('TLP cao nhất được gửi cho ứng dụng AI')).toBeTruthy()
    expect(screen.getByText('Chính sách')).toBeTruthy()
  })
})
