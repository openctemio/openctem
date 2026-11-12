import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const perms = { pair: true }
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, useHasPermission: () => perms.pair }
})

import { ApproveSensorButton } from '../add-sensor-dialog'

describe('ApproveSensorButton', () => {
  it('links to the approve page for users who can pair', () => {
    perms.pair = true
    render(<ApproveSensorButton />)
    const link = screen.getByRole('link', { name: /approve a sensor/i })
    expect(link.getAttribute('href')).toBe('/activate')
  })

  it('is hidden without sensors:pair', () => {
    perms.pair = false
    render(<ApproveSensorButton />)
    expect(screen.queryByRole('link')).toBeNull()
  })
})
