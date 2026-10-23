import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ExposureDetailsView } from '../exposure-details-view'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/credentials', () => ({ LeakedSecretField: () => <div>leaked-field</div> }))

describe('ExposureDetailsView', () => {
  it('shows the server mask and offers no reveal toggle or copy for it', () => {
    render(
      <ExposureDetailsView
        details={{ password: '********', host: 'db.internal', nested_note: 'x' }}
      />
    )
    expect(screen.getByText('********')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /reveal|hide secrets/i })).toBeNull()
    expect(screen.queryByText(/reveal secrets/i)).toBeNull()
    // Copy buttons exist for plain values only, each with an accessible name.
    const copies = screen.getAllByRole('button', { name: 'Copy value' })
    expect(copies).toHaveLength(2)
  })

  it('renders the leaked credential through the audited field', () => {
    render(
      <ExposureDetailsView
        details={{ secret_masked: 'ab****', secret_fingerprint: 'fp' }}
        leakedCredentialId="c1"
      />
    )
    expect(screen.getByText('leaked-field')).toBeInTheDocument()
  })
})
