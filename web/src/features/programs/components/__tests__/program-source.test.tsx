import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({
  setProgramSource: vi.fn(),
  syncProgram: vi.fn(),
}))
vi.mock('../../api/use-programs', () => api)
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback: string, vars?: Record<string, unknown>) =>
      fallback.replace(/\{(\w+)\}/g, (_m, v: string) => String(vars?.[v] ?? '')),
  }),
}))

import { toast } from 'sonner'
import { ProgramSource } from '../program-source'
import type { Program } from '../../api/programs-api.types'

function program(over: Partial<Program> = {}): Program {
  return {
    id: 'p1',
    name: 'Acme',
    platform: 'self',
    handle: 'jdoe',
    program_url: 'https://acme.example/security',
    status: 'active',
    scope_source: 'program_api',
    authoritative: true,
    rules: {},
    max_tier: 't1',
    terms_sha256: 'a'.repeat(64),
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    sync: { handle: 'acme', username: 'jdoe', has_token: true, last_error: 'HTTP 401' },
    ...over,
  }
}

describe('ProgramSource', () => {
  beforeEach(() => {
    api.setProgramSource.mockReset()
    api.syncProgram.mockReset()
  })

  it('shows the source without ever showing the token, and the last error', () => {
    render(<ProgramSource program={program()} canWrite onChanged={() => {}} />)
    expect(screen.getByText('Platform researcher API')).toBeInTheDocument()
    expect(screen.getByText('Stored (encrypted, never shown)')).toBeInTheDocument()
    expect(screen.getByText('HTTP 401')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Sync now/ })).toBeInTheDocument()
  })

  it('offers no sync for a pasted scope, and no actions without write', () => {
    const { unmount } = render(
      <ProgramSource
        program={program({ scope_source: 'paste', sync: undefined })}
        canWrite
        onChanged={() => {}}
      />
    )
    expect(screen.queryByRole('button', { name: /Sync now/ })).toBeNull()
    unmount()
    render(<ProgramSource program={program()} canWrite={false} onChanged={() => {}} />)
    expect(screen.queryByRole('button', { name: /Sync now/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Change source/ })).toBeNull()
  })

  it('keeps the stored token when the field is left empty', async () => {
    api.setProgramSource.mockResolvedValue(program())
    const onChanged = vi.fn()
    render(<ProgramSource program={program()} canWrite onChanged={onChanged} />)
    await userEvent.click(screen.getByRole('button', { name: /Change source/ }))
    await userEvent.click(screen.getByRole('button', { name: /Save source/ }))
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(api.setProgramSource).toHaveBeenCalledWith('p1', {
      scope_source: 'program_api',
      url: undefined,
      handle: 'acme',
      username: 'jdoe',
      token: undefined,
    })
  })

  it('reports what a sync did', async () => {
    api.syncProgram.mockResolvedValue({
      program: program(),
      removed_entries: 2,
      added_exclusions: 1,
      pending_additions: 3,
      suspended: false,
    })
    render(<ProgramSource program={program()} canWrite onChanged={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: /Sync now/ }))
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        'Synced: 2 entries removed, 1 exclusions added, 3 additions waiting for acceptance.'
      )
    )
  })
})
