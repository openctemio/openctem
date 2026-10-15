/**
 * The inbound Jira webhook dialog: the URL to paste into Jira, a secret shown
 * once after it is generated (never fetched back), and an entered secret
 * sent to the API.
 */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const m = vi.hoisted(() => ({
  hasSecret: false,
  rotate: vi.fn(),
  save: vi.fn(),
}))

vi.mock('../../api/use-integrations-api', () => ({
  useJiraWebhookApi: () => ({
    data: {
      webhook_url: '/hooks/jira-integrations/int-1',
      signature_header: 'X-Hub-Signature',
      has_secret: m.hasSecret,
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useRotateJiraWebhookSecretApi: () => ({ trigger: m.rotate, isMutating: false }),
  useSetJiraWebhookSecretApi: () => ({ trigger: m.save, isMutating: false }),
}))

import { JiraWebhookDialog, absoluteWebhookUrl } from '../jira-webhook-dialog'
import type { Integration } from '../../types/integration.types'

const integration = { id: 'int-1', name: 'Jira Cloud', provider: 'jira' } as unknown as Integration

describe('JiraWebhookDialog', () => {
  it('builds the absolute URL from the console origin', () => {
    expect(absoluteWebhookUrl('/hooks/jira-integrations/x', 'https://ctem.example.com/')).toBe(
      'https://ctem.example.com/hooks/jira-integrations/x'
    )
  })

  it('shows the URL and, after a rotation, the new secret once', async () => {
    m.rotate.mockResolvedValue({ webhook_secret: 'a'.repeat(64), has_secret: true })
    render(<JiraWebhookDialog integration={integration} open onOpenChange={() => {}} />)
    expect(screen.getByText(/\/hooks\/jira-integrations\/int-1$/)).toBeTruthy()
    expect(screen.queryByText('a'.repeat(64))).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Generate a secret/ }))
    await waitFor(() => expect(screen.getByText('a'.repeat(64))).toBeTruthy())
    expect(m.rotate).toHaveBeenCalledTimes(1)
  })

  it('sends an entered secret only when it is long enough', async () => {
    m.save.mockResolvedValue({ has_secret: true })
    render(<JiraWebhookDialog integration={integration} open onOpenChange={() => {}} />)
    const input = screen.getByLabelText(/Or enter the secret from Jira/)
    const save = screen.getByRole('button', { name: 'Save secret' })
    fireEvent.change(input, { target: { value: 'short' } })
    expect((save as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(input, { target: { value: 'secret-from-jira-0123' } })
    fireEvent.click(save)
    await waitFor(() => expect(m.save).toHaveBeenCalledWith({ secret: 'secret-from-jira-0123' }))
  })
})
