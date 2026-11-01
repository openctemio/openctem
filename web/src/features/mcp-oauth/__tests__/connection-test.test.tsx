import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ConnectionTest } from '../components/connection-test'

const fetchMine = vi.hoisted(() => vi.fn())
vi.mock('../api/connections', () => ({ fetchMyConnections: fetchMine }))

describe('Test connection', () => {
  beforeEach(() => {
    fetchMine.mockReset()
    fetchMine.mockResolvedValue({ data: [] })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, json: async () => ({}) }))
    )
  })

  it('sends no API request until the person presses the button', async () => {
    render(<ConnectionTest />)
    expect(fetchMine).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button'))
    await waitFor(() => expect(fetchMine).toHaveBeenCalledTimes(1))
  })
})
