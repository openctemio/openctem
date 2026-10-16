import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ContentCatalogSettings, ContentTrust } from '@/lib/api/generated'

let perms = new Set<string>()
let settings: ContentCatalogSettings | undefined

vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.has(p) }) }
})

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  useContentSettings: () => ({ data: settings, error: undefined, mutate: vi.fn() }),
  putContentSettings: vi.fn(),
}))

import { Permission } from '@/lib/permissions'
import { ApprovalSettings } from '../components/approval-settings'
import { TrustBanner } from '../components/trust-banner'

describe('ApprovalSettings', () => {
  beforeEach(() => {
    perms = new Set([Permission.ContentRead, Permission.SettingsWrite])
    settings = { require_approval: true }
  })

  it('shows the switch on and no pending notice while approval is on', () => {
    render(<ApprovalSettings />)
    const sw = screen.getByRole('switch', { name: /require approval/i })
    expect(sw).toBeChecked()
    expect(sw).toBeEnabled()
    expect(screen.queryByText(/will be switched off at/i)).toBeNull()
  })

  it('shows a pending switch-off with its time and how to cancel', () => {
    settings = { require_approval: true, approval_off_at: '2026-10-17T10:00:00Z' }
    render(<ApprovalSettings />)
    expect(screen.getByRole('switch', { name: /require approval/i })).not.toBeChecked()
    expect(screen.getByText(/approval will be switched off at .*2026/i)).toBeInTheDocument()
    expect(screen.getByText(/turn it back on to cancel/i)).toBeInTheDocument()
  })

  it('disables the switch without settings:write', () => {
    perms = new Set([Permission.ContentRead])
    render(<ApprovalSettings />)
    expect(screen.getByRole('switch', { name: /require approval/i })).toBeDisabled()
  })
})

describe('TrustBanner', () => {
  const current = {
    roots_configured: 1,
    imported_at: '2026-10-01T00:00:00Z',
    index_expired: false,
    revocations_stale: false,
  } as ContentTrust

  it('renders nothing for a current catalog', () => {
    const { container } = render(<TrustBanner trust={current} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('warns about a stale revocation list', () => {
    render(<TrustBanner trust={{ ...current, revocations_stale: true }} />)
    expect(screen.getByText(/out of date/i)).toBeInTheDocument()
    expect(screen.getByText(/revocation list is past its expiry/i)).toBeInTheDocument()
  })

  it('explains an instance with no trust root', () => {
    render(<TrustBanner trust={{ ...current, roots_configured: 0 }} />)
    expect(screen.getByText(/not set up/i)).toBeInTheDocument()
  })
})
