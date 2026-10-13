import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { SensorGrantSuggestion } from '@/lib/api/sensor-grant-hooks'

const api = vi.hoisted(() => ({
  suggestion: undefined as unknown,
  apply: vi.fn(),
  mutate: vi.fn(async () => undefined),
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
}))

vi.mock('sonner', () => ({ toast: { success: api.toastSuccess, error: api.toastError } }))
vi.mock('@/lib/api/sensor-grant-hooks', async (orig) => {
  const real = await orig<typeof import('@/lib/api/sensor-grant-hooks')>()
  return {
    ...real,
    useSensorGrantSuggestion: () => ({ data: api.suggestion, mutate: api.mutate }),
    applySensorGrantSuggestion: api.apply,
  }
})

import { SensorGrantSuggestionCard } from '../sensor-grant-suggestion-card'

function suggestion(over: Partial<SensorGrantSuggestion> = {}): SensorGrantSuggestion {
  return {
    sensor_id: 's1',
    available: true,
    profile: 'easm-external',
    current_profile: 'legacy-broad',
    current_version: 3,
    changed: ['job_types', 'target_network', 'tier_ceiling'],
    window_days: 30,
    usage: {
      job_count: 12,
      job_types: ['scan'],
      tools: ['httpx', 'subfinder'],
      max_tier: 1,
      private_targets: false,
      public_targets: true,
      zone_count: 0,
      push_ingest: false,
      complete: true,
    },
    ...over,
  }
}

describe('SensorGrantSuggestionCard', () => {
  beforeEach(() => {
    api.apply.mockReset()
    api.mutate.mockClear()
    api.toastError.mockClear()
  })

  it('shows the suggestion with its usage and applies the version and profile it read', async () => {
    api.suggestion = suggestion()
    api.apply.mockResolvedValue({ profile: 'easm-external', version: 4 })
    const onApplied = vi.fn()
    render(<SensorGrantSuggestionCard sensorId="s1" legacyBroad onApplied={onApplied} />)

    expect(screen.getByTestId('grant-suggestion')).toHaveAttribute('data-available', 'true')
    expect(screen.getByText(/12 jobs: scan/)).toBeInTheDocument()
    expect(screen.getByText('Public targets only')).toBeInTheDocument()
    expect(screen.getByText('Based on the last 30 days')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Apply suggested grant' }))
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() =>
      expect(api.apply).toHaveBeenCalledWith('s1', { version: 3, profile: 'easm-external' })
    )
    expect(onApplied).toHaveBeenCalledWith({ profile: 'easm-external', version: 4 })
  })

  it('reloads on a changed suggestion (409) and keeps the grant as it was', async () => {
    api.suggestion = suggestion()
    api.apply.mockRejectedValue({ statusCode: 409, message: 'changed' })
    const onApplied = vi.fn()
    render(<SensorGrantSuggestionCard sensorId="s1" legacyBroad onApplied={onApplied} />)
    await userEvent.click(screen.getByRole('button', { name: 'Apply suggested grant' }))
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(api.toastError).toHaveBeenCalled())
    expect(api.mutate).toHaveBeenCalled()
    expect(onApplied).not.toHaveBeenCalled()
  })

  it('explains a legacy sensor no profile fits, and stays silent otherwise', () => {
    api.suggestion = suggestion({ available: false, profile: '', reason: 'no_profile_fits' })
    const { rerender } = render(
      <SensorGrantSuggestionCard sensorId="s1" legacyBroad onApplied={vi.fn()} />
    )
    expect(screen.getByTestId('grant-suggestion')).toHaveAttribute('data-available', 'false')
    expect(screen.queryByRole('button', { name: 'Apply suggested grant' })).toBeNull()

    rerender(<SensorGrantSuggestionCard sensorId="s1" legacyBroad={false} onApplied={vi.fn()} />)
    expect(screen.queryByTestId('grant-suggestion')).toBeNull()

    api.suggestion = suggestion({ available: false, profile: '', reason: 'already_narrowest' })
    rerender(<SensorGrantSuggestionCard sensorId="s1" legacyBroad onApplied={vi.fn()} />)
    expect(screen.queryByTestId('grant-suggestion')).toBeNull()
  })
})
