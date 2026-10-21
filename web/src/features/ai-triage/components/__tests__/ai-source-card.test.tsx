import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AISourceCard } from '../ai-source-card'
import type { AISettings } from '../../api/use-ai-settings'

// Radix Select and RadioGroup measure themselves; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

const update = vi.fn()
const testProvider = vi.fn()
const toastError = vi.fn()

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a) },
}))
vi.mock('../../api/use-ai-settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api/use-ai-settings')>()),
  updateAISettings: (...a: unknown[]) => update(...a),
  testAIProvider: (...a: unknown[]) => testProvider(...a),
}))

const base: AISettings = {
  enabled: true,
  source: 'platform',
  provider: '',
  base_url: '',
  model: '',
  key: { set: false },
  own_provider_allowed: true,
  providers: ['claude', 'openai', 'gemini', 'openai_compatible'],
}

describe('AI source', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has three sources and no provider form until Own provider is chosen', async () => {
    render(<AISourceCard settings={base} canEdit onSaved={vi.fn()} />)
    expect(screen.getByRole('radio', { name: /Platform AI/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /Own provider/ })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /Off/ })).toBeInTheDocument()
    expect(screen.queryByLabelText('API key')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('radio', { name: /Own provider/ }))
    expect(screen.getByLabelText('API key')).toHaveAttribute('type', 'password')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('shows a saved key only as set, last four and date, never the key', () => {
    render(
      <AISourceCard
        settings={{
          ...base,
          source: 'own',
          provider: 'openai',
          model: 'gpt-4o',
          key: { set: true, last4: '6789', updated_at: '2026-10-19T00:00:00Z' },
        }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    expect(screen.getByText(/ends in 6789/)).toBeInTheDocument()
    expect(screen.getByLabelText('API key')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeEnabled()
  })

  it('saves an OpenAI-compatible provider with a base URL and no key', async () => {
    const onSaved = vi.fn()
    update.mockResolvedValue({ ...base, source: 'own' })
    render(
      <AISourceCard
        settings={{ ...base, source: 'own', provider: 'openai_compatible' }}
        canEdit
        onSaved={onSaved}
      />
    )
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Model'), 'llama3')
    await userEvent.type(screen.getByLabelText('Base URL'), 'https://llm.example.com/v1')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({
        source: 'own',
        provider: 'openai_compatible',
        base_url: 'https://llm.example.com/v1',
        model: 'llama3',
      })
    )
    expect(onSaved).toHaveBeenCalled()
  })

  it('sends a typed key once and does not keep it in the form after saving', async () => {
    update.mockResolvedValue({
      ...base,
      source: 'own',
      provider: 'openai',
      key: { set: true, last4: '6789' },
    })
    const { rerender } = render(
      <AISourceCard
        settings={{ ...base, source: 'own', provider: 'openai' }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    await userEvent.type(screen.getByLabelText('API key'), 'sk-fake-secret-0123456789')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith(
        expect.objectContaining({ api_key: 'sk-fake-secret-0123456789' })
      )
    )
    rerender(
      <AISourceCard
        settings={{ ...base, source: 'own', provider: 'openai', key: { set: true, last4: '6789' } }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    expect(screen.getByLabelText('API key')).toHaveValue('')
  })

  it('tests the connection and says why it failed with a translated message', async () => {
    testProvider.mockResolvedValue({ ok: false, code: 'blocked_address' })
    render(
      <AISourceCard
        settings={{
          ...base,
          source: 'own',
          provider: 'openai_compatible',
          base_url: 'https://x.example.com/v1',
          model: 'm',
        }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }))
    expect(
      await screen.findByText(/not allowed: it must be a public https address/)
    ).toBeInTheDocument()
    expect(testProvider).toHaveBeenCalledWith({
      provider: 'openai_compatible',
      base_url: 'https://x.example.com/v1',
      model: 'm',
    })
  })

  it('an unsaved provider change needs a new key (the saved key is not carried over)', async () => {
    render(
      <AISourceCard
        settings={{ ...base, source: 'own', provider: 'openai', key: { set: true, last4: '6789' } }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    await userEvent.click(screen.getByRole('combobox', { name: 'Provider' }))
    await userEvent.click(await screen.findByRole('option', { name: 'Google Gemini' }))
    expect(screen.getByText(/saved key belongs to the previous provider/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('disables Own provider when the platform forbids it, and warns when it was in use', () => {
    const { unmount } = render(
      <AISourceCard settings={{ ...base, own_provider_allowed: false }} canEdit onSaved={vi.fn()} />
    )
    expect(screen.getByRole('radio', { name: /Own provider/ })).toBeDisabled()
    unmount()
    render(
      <AISourceCard
        settings={{ ...base, source: 'own', provider: 'openai', own_provider_allowed: false }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    expect(screen.getByRole('alert')).toHaveTextContent(/no longer allows own providers/)
  })

  it('is read-only without permission', () => {
    render(
      <AISourceCard
        settings={{ ...base, source: 'own', provider: 'openai' }}
        canEdit={false}
        onSaved={vi.fn()}
      />
    )
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('API key')).toBeDisabled()
  })
})
