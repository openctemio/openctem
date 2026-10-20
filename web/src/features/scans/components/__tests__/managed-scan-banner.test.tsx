/**
 * A scan a platform policy owns: the banner names the policy, points to the
 * coverage settings (continuous coverage only) and offers no way to take it
 * over. Nothing shows for a person's scan.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ManagedScanBanner } from '../managed-scan-banner'

describe('ManagedScanBanner', () => {
  it("renders nothing for a person's scan", () => {
    const { container } = render(<ManagedScanBanner config={{ owner_state: 'ok' }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('names continuous coverage and links to the coverage settings', () => {
    render(<ManagedScanBanner config={{ managed_by: 'coverage', owner_state: 'managed' }} />)
    expect(screen.getByTestId('managed-scan-banner')).toHaveTextContent(
      'Managed by the platform · Continuous coverage'
    )
    expect(screen.getByRole('link', { name: 'Open coverage settings' })).toHaveAttribute(
      'href',
      '/settings/scope'
    )
    expect(screen.queryByRole('button', { name: 'Take ownership' })).toBeNull()
  })

  it('names automatic enrichment and links nowhere', () => {
    render(<ManagedScanBanner config={{ managed_by: 'enrichment', owner_state: 'managed' }} />)
    expect(screen.getByTestId('managed-scan-banner')).toHaveTextContent(
      'Managed by the platform · Automatic enrichment'
    )
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('treats owner_state managed alone as managed', () => {
    render(<ManagedScanBanner config={{ owner_state: 'managed' }} />)
    expect(screen.getByTestId('managed-scan-banner')).toBeInTheDocument()
  })
})
