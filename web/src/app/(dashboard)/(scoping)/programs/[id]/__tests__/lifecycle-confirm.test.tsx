import { Suspense } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { endProgram, suspendProgram } from '@/features/programs'
import ProgramPage from '../page'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: () => undefined,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  usePermissions: () => ({ isOwner: () => true }),
}))
const program = {
  id: 'p1',
  name: 'Acme VDP',
  platform: 'self',
  status: 'active',
  terms_sha256: 'b'.repeat(64),
  items: [],
  exclusions: [],
  entries: [],
  rules: { forbidden: [] },
  visibility: 'private',
}
vi.mock('@/features/programs', async (orig) => {
  const real = await orig<typeof import('@/features/programs')>()
  const Null = () => null
  return {
    ...real,
    ProgramExclusionsTable: Null,
    ProgramTargetsTable: Null,
    ProgramNotifications: Null,
    ProgramPendingTerms: Null,
    ProgramSource: Null,
    ProgramSuggestions: Null,
    ProgramLocked: Null,
    ProgramForm: Null,
    useProgram: () => ({ data: program, error: undefined, mutate: vi.fn() }),
    invalidatePrograms: vi.fn(),
    suspendProgram: vi.fn(() => Promise.resolve()),
    endProgram: vi.fn(() => Promise.resolve()),
  }
})
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// Already settled, so React's use() reads it without suspending.
const params = Object.assign(Promise.resolve({ id: 'p1' }), {
  status: 'fulfilled',
  value: { id: 'p1' },
})

async function renderPage() {
  render(
    <Suspense fallback={null}>
      <ProgramPage params={params} />
    </Suspense>
  )
  return screen.findByRole('button', { name: 'End' })
}

describe('Program lifecycle actions', () => {
  it('ending a program asks first and names it', async () => {
    await userEvent.click(await renderPage())
    expect(endProgram).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('End the program "Acme VDP"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'End program' }))
    await waitFor(() => expect(endProgram).toHaveBeenCalledWith('p1'))
  })

  it('suspending asks first; Cancel suspends nothing', async () => {
    await renderPage()
    await userEvent.click(screen.getByRole('button', { name: 'Suspend' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Suspend the program "Acme VDP"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(suspendProgram).not.toHaveBeenCalled()
  })
})
