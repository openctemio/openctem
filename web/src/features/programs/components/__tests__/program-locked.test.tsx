import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({ attestProgram: vi.fn() }))
vi.mock('../../api/use-programs', () => api)
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback: string, vars?: Record<string, unknown>) =>
      fallback.replace(/\{(\w+)\}/g, (_m, v: string) => String(vars?.[v] ?? '')),
  }),
}))

import { ProgramLocked } from '../program-locked'
import type { Program } from '../../api/programs-api.types'

const locked: Program = {
  id: 'p1',
  name: 'Invite-only',
  platform: 'self',
  handle: '',
  program_url: '',
  visibility: 'private',
  terms_text: 'Do not disclose this program.',
  locked: true,
  status: 'active',
  scope_source: 'file_import',
  authoritative: false,
  rules: {},
  max_tier: '',
  terms_sha256: 'b'.repeat(64),
  created_at: '2026-10-10T00:00:00Z',
  updated_at: '2026-10-10T00:00:00Z',
}

describe('ProgramLocked', () => {
  beforeEach(() => api.attestProgram.mockReset())

  it('shows the terms and accepts them only after the box is ticked, with the terms hash', async () => {
    api.attestProgram.mockResolvedValue({ ...locked, locked: false })
    const onAccepted = vi.fn()
    render(<ProgramLocked program={locked} onAccepted={onAccepted} />)
    expect(screen.getByText('Do not disclose this program.')).toBeInTheDocument()
    const button = screen.getByRole('button', { name: /Accept and open/ })
    expect(button).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(button)
    await waitFor(() => expect(api.attestProgram).toHaveBeenCalledWith('p1', 'b'.repeat(64)))
    expect(onAccepted).toHaveBeenCalled()
  })
})
