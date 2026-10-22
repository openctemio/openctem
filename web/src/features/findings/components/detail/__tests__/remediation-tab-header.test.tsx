/** The remediation tab has no fake "Remediation Progress / No tracked steps" header. */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => false }),
}))
vi.mock('../../../api/use-finding-evidence', () => ({
  useAddRemediationStep: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('../mobilization-brief-card', () => ({ MobilizationBriefCard: () => null }))

const { RemediationTab } = await import('../remediation-tab')

describe('RemediationTab', () => {
  it('renders no progress header when there are no tracked steps', () => {
    render(
      <RemediationTab
        remediation={{ description: 'Upgrade it', steps: [], references: [], progress: 0 }}
      />
    )
    expect(screen.queryByText('Remediation Progress')).not.toBeInTheDocument()
    expect(screen.queryByText('No tracked remediation steps')).not.toBeInTheDocument()
  })
})
