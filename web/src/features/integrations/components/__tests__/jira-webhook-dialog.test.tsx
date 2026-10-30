/**
 * The inbound Jira webhook dialog: the URL to paste into Jira, a secret shown
 * once after it is generated (never fetched back), and an entered secret
 * sent to the API.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
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
  beforeEach(() => {
    m.hasSecret = false
  })

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

  describe('when a secret is already set', () => {
    it('asks before generating a new one: the old one stops at once', async () => {
      m.hasSecret = true
      m.rotate.mockReset().mockResolvedValue({ webhook_secret: 'b'.repeat(64), has_secret: true })
      render(<JiraWebhookDialog integration={integration} open onOpenChange={() => {}} />)
      fireEvent.click(screen.getByRole('button', { name: 'Generate a new secret' }))
      const dialog = await screen.findByRole('alertdialog')
      expect(dialog.textContent).toContain('stops working at once')
      expect(m.rotate).not.toHaveBeenCalled()
      fireEvent.click(screen.getByRole('button', { name: 'Generate new secret' }))
      await waitFor(() => expect(m.rotate).toHaveBeenCalledTimes(1))
    })

    it('Cancel keeps the current secret', async () => {
      m.hasSecret = true
      m.rotate.mockReset()
      render(<JiraWebhookDialog integration={integration} open onOpenChange={() => {}} />)
      fireEvent.click(screen.getByRole('button', { name: 'Generate a new secret' }))
      fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
      expect(m.rotate).not.toHaveBeenCalled()
    })

    it('asks before replacing it with an entered one', async () => {
      m.hasSecret = true
      m.save.mockReset().mockResolvedValue({ has_secret: true })
      render(<JiraWebhookDialog integration={integration} open onOpenChange={() => {}} />)
      fireEvent.change(screen.getByLabelText(/Or enter the secret from Jira/), {
        target: { value: 'secret-from-jira-0123' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Save secret' }))
      await screen.findByRole('alertdialog')
      expect(m.save).not.toHaveBeenCalled()
      fireEvent.click(screen.getByRole('button', { name: 'Replace secret' }))
      await waitFor(() => expect(m.save).toHaveBeenCalledWith({ secret: 'secret-from-jira-0123' }))
    })
  })
})
