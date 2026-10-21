/**
 * The ticket create policy dialog: shows the stored policy and its counts,
 * previews a change, refuses an invalid daily limit and saves the edited
 * policy.
 */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const m = vi.hoisted(() => ({
  save: vi.fn(),
  preview: vi.fn(),
}))

vi.mock('../../api/use-ticket-create-policy', () => ({
  MAX_DAILY_CAP: 10000,
  useTicketCreatePolicy: () => ({
    data: {
      policy: {
        min_severity: 'medium',
        min_priority_class: 'P2',
        always_kev: true,
        daily_cap: 200,
      },
      defaults: {
        min_severity: 'medium',
        min_priority_class: 'P2',
        always_kev: true,
        daily_cap: 200,
      },
      stored: false,
      stats: { held_by_reason: { below_threshold: 7, daily_cap: 3 }, created_today: 12 },
    },
    isLoading: false,
  }),
  saveTicketCreatePolicy: m.save,
  previewTicketCreatePolicy: m.preview,
}))

import { TicketCreatePolicyDialog } from '../ticket-create-policy-dialog'
import type { Integration } from '../../types/integration.types'

const integration = { id: 'int-1', name: 'Jira Cloud', provider: 'jira' } as unknown as Integration

describe('TicketCreatePolicyDialog', () => {
  it('shows the counts and previews the policy', async () => {
    m.preview.mockResolvedValue({
      last_30_days_total: 40,
      last_30_days_pass: 9,
      held_now: 7,
      held_would_pass: 2,
    })
    render(<TicketCreatePolicyDialog integration={integration} open onOpenChange={() => {}} />)
    expect(screen.getByText('Created today: 12')).toBeTruthy()
    expect(screen.getByText('Below the policy: 7')).toBeTruthy()
    expect(screen.getByText('Waiting for the daily limit: 3')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }))
    await waitFor(() =>
      expect(
        screen.getByText('Of 40 findings first seen in the last 30 days, 9 would get an issue.')
      ).toBeTruthy()
    )
    expect(m.preview).toHaveBeenCalledWith('int-1', {
      min_severity: 'medium',
      min_priority_class: 'P2',
      always_kev: true,
      daily_cap: 200,
    })
  })

  it('refuses an invalid daily limit and saves a valid one', async () => {
    m.save.mockResolvedValue({})
    const onOpenChange = vi.fn()
    render(<TicketCreatePolicyDialog integration={integration} open onOpenChange={onOpenChange} />)
    const cap = screen.getByLabelText('Daily limit')
    const save = screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement
    fireEvent.change(cap, { target: { value: '-5' } })
    expect(save.disabled).toBe(true)
    fireEvent.change(cap, { target: { value: '0' } })
    fireEvent.click(screen.getByRole('switch'))
    fireEvent.click(save)
    await waitFor(() =>
      expect(m.save).toHaveBeenCalledWith('int-1', {
        min_severity: 'medium',
        min_priority_class: 'P2',
        always_kev: false,
        daily_cap: 0,
      })
    )
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
  })
})
