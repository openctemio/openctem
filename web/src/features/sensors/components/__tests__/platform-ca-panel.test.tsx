import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { PLATFORM_CA_DOWNLOAD_PATH, PlatformCAPanel } from '../platform-ca-panel'

const root = 'ab'.repeat(32)

describe('PlatformCAPanel', () => {
  it('lists each certificate with its SHA-256, marks the pinned root and links the bundle', () => {
    render(
      <PlatformCAPanel
        ca={{
          pin: root,
          download_path: 'https://evil.example/ca.pem',
          certificates: [
            {
              common_name: 'Test Root',
              sha256: 'AB:'.repeat(31) + 'AB',
              sha256_hex: root,
              root: true,
              not_after: '2036-08-09T14:58:23Z',
            },
          ],
        }}
      />
    )
    expect(screen.getByText('Test Root')).toBeInTheDocument()
    expect(screen.getByText('Root')).toBeInTheDocument()
    expect(screen.getByText('Pinned')).toBeInTheDocument()
    expect(screen.getByText('AB:'.repeat(31) + 'AB')).toBeInTheDocument()
    // The link target is a constant, never the answer's download_path.
    const link = screen.getByRole('link', { name: 'Download CA certificates' })
    expect(link).toHaveAttribute('href', PLATFORM_CA_DOWNLOAD_PATH)
    expect(link.getAttribute('href')).toBe('/api/v1/sensors/platform-ca')
  })

  it('does not mark an intermediate or an unpinned root as pinned', () => {
    render(
      <PlatformCAPanel
        ca={{
          pin: '',
          download_path: '/api/v1/sensors/platform-ca',
          certificates: [
            {
              common_name: 'Expired Root',
              sha256: 'EF:'.repeat(31) + 'EF',
              sha256_hex: 'ef'.repeat(32),
              root: true,
              not_after: '2020-01-01T00:00:00Z',
            },
            {
              common_name: 'Intermediate',
              sha256: 'CD:'.repeat(31) + 'CD',
              sha256_hex: 'cd'.repeat(32),
              root: false,
              not_after: '2036-01-01T00:00:00Z',
            },
          ],
        }}
      />
    )
    expect(screen.queryByText('Pinned')).toBeNull()
    // The name and the badge.
    expect(screen.getAllByText('Intermediate')).toHaveLength(2)
  })
})
