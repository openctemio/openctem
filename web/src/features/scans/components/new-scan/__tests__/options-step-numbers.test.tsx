import { useState } from 'react'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../../types'
import { OptionsStep } from '../options-step'

vi.mock('@/lib/api/platform-hooks', () => ({ usePlatformScanning: () => ({ offered: false }) }))
vi.mock('@/lib/api/scan-profile-hooks', () => ({ useScanProfiles: () => ({ data: undefined }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))

function Harness({
  initial,
  seen,
}: {
  initial: Partial<NewScanFormData>
  seen: NewScanFormData[]
}) {
  const [data, setData] = useState<NewScanFormData>({ ...DEFAULT_NEW_SCAN, ...initial })
  return (
    <OptionsStep
      data={data}
      onChange={(patch) =>
        setData((prev) => {
          const next = { ...prev, ...patch }
          seen.push(next)
          return next
        })
      }
    />
  )
}

async function openAdvanced() {
  await userEvent.click(screen.getByRole('button', { name: /Advanced/ }))
}

describe('OptionsStep number fields', () => {
  it('a max duration typed digit by digit is kept as typed (3600, not 30600)', async () => {
    const seen: NewScanFormData[] = []
    render(<Harness initial={{ timeoutSeconds: 0 }} seen={seen} />)
    await openAdvanced()
    const input = screen.getByLabelText(/Max duration|Timeout/i)
    await userEvent.type(input, '3600')
    expect(input).toHaveValue(3600)
    fireEvent.blur(input)
    expect(seen.at(-1)?.timeoutSeconds).toBe(3600)
    expect(input).toHaveValue(3600)
  })

  it('clamps on leaving the field and clears to "none"', async () => {
    const seen: NewScanFormData[] = []
    render(<Harness initial={{ timeoutSeconds: 600 }} seen={seen} />)
    await openAdvanced()
    const input = screen.getByLabelText(/Max duration|Timeout/i)
    await userEvent.clear(input)
    await userEvent.type(input, '10')
    fireEvent.blur(input)
    expect(seen.at(-1)?.timeoutSeconds).toBe(30)
    await userEvent.clear(input)
    fireEvent.blur(input)
    expect(seen.at(-1)?.timeoutSeconds).toBe(0)
    expect(input).toHaveValue(null)
  })

  it('a retry backoff typed digit by digit is kept as typed (120)', async () => {
    const seen: NewScanFormData[] = []
    render(<Harness initial={{ maxRetries: 2, retryBackoffSeconds: 60 }} seen={seen} />)
    await openAdvanced()
    const input = screen.getByLabelText(/backoff/i)
    await userEvent.clear(input)
    await userEvent.type(input, '120')
    fireEvent.blur(input)
    expect(seen.at(-1)?.retryBackoffSeconds).toBe(120)
  })
})
