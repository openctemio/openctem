import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({
  subscribeProgram: vi.fn(),
  useProgramCatalog: vi.fn(),
}))
vi.mock('../../api/use-programs', () => api)
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback: string, vars?: Record<string, unknown>) =>
      fallback.replace(/\{(\w+)\}/g, (_m, v: string) => String(vars?.[v] ?? '')),
  }),
}))

import { ProgramCatalog } from '../program-catalog'

const pub = {
  id: 'pp1',
  feed_id: 'acme-bounty:acme',
  platform: 'acme-bounty',
  handle: 'acme',
  name: 'Acme public',
  url: 'https://acme-bounty.example/acme',
  source: 'disclose',
  type: 'bounty' as const,
  status: 'open' as const,
  scope_published: true,
  offers_bounty: true,
  in_scope: 3,
  suggested: 2,
  out_of_scope: 1,
  provenance: {
    source: 'disclose',
    source_url: 'https://acme-bounty.example/list.json',
    fetched_at: '2026-10-10T00:00:00Z',
    original_platform: 'acme-bounty',
  },
  items: [],
  rules: {},
  terms_text: '',
  as_of: '2026-10-10T00:00:00Z',
}

describe('ProgramCatalog', () => {
  beforeEach(() => {
    api.subscribeProgram.mockReset()
    api.useProgramCatalog.mockReturnValue({
      data: { data: [pub], total: 1, page: 1, per_page: 50 },
      isLoading: false,
    })
  })

  it('lists published programs and follows one', async () => {
    const change = { program: { id: 'p9' }, preview: {} }
    api.subscribeProgram.mockResolvedValue(change)
    const onFollowed = vi.fn()
    render(<ProgramCatalog onFollowed={onFollowed} onError={() => {}} />)
    expect(screen.getByText('Acme public')).toBeInTheDocument()
    expect(screen.getByText(/3 in scope, 2 suggested, 1 out of scope/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Follow' }))
    await waitFor(() => expect(api.subscribeProgram).toHaveBeenCalledWith('pp1'))
    expect(onFollowed).toHaveBeenCalledWith(change)
  })

  it('shows an empty state when the catalog is empty', () => {
    api.useProgramCatalog.mockReturnValue({ data: { data: [], total: 0 }, isLoading: false })
    render(<ProgramCatalog onFollowed={() => {}} onError={() => {}} />)
    expect(screen.getByText('No public programs')).toBeInTheDocument()
  })
})
