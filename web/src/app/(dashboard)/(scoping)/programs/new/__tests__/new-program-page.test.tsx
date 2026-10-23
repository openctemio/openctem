import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import NewProgramPage from '../page'

let canWrite = false
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => canWrite,
}))
vi.mock('@/features/programs', () => ({
  ProgramForm: () => <div data-testid="program-form" />,
  importProgram: vi.fn(),
  invalidatePrograms: vi.fn(),
}))

describe('new program page', () => {
  it('shows no form without programs:write', () => {
    canWrite = false
    render(<NewProgramPage />)
    expect(screen.queryByTestId('program-form')).toBeNull()
    expect(screen.getByText(/you do not have access to import program/i)).toBeInTheDocument()
  })

  it('titles the page like its entry button and links back with Cancel', () => {
    canWrite = true
    render(<NewProgramPage />)
    expect(screen.getByTestId('program-form')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Import program' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Cancel' })).toHaveAttribute('href', '/programs')
  })
})
