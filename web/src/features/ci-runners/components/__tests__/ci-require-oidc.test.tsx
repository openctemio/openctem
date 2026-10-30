import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({
  settings: { require_oidc: true } as { require_oidc: boolean },
  save: vi.fn(),
  mutate: vi.fn(async () => undefined),
}))
vi.mock('../../api/use-ci', () => ({
  useCISettings: () => ({ data: api.settings, error: undefined, mutate: api.mutate }),
  useSaveCISettings: () => ({ trigger: api.save, isMutating: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { CIRequireOIDC } from '../ci-require-oidc'

describe('CIRequireOIDC', () => {
  beforeEach(() => {
    api.save.mockReset().mockResolvedValue({ require_oidc: false })
    api.settings = { require_oidc: true }
  })

  it('switching it off asks first, naming what gets weaker', async () => {
    const user = userEvent.setup()
    render(<CIRequireOIDC canWrite />)
    await user.click(screen.getByRole('switch', { name: 'Require OIDC for CI' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Accept CI sensor keys again?')
    expect(api.save).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Accept CI keys' }))
    await waitFor(() => expect(api.save).toHaveBeenCalledWith({ require_oidc: false }))
  })

  it('Cancel keeps OIDC required', async () => {
    const user = userEvent.setup()
    render(<CIRequireOIDC canWrite />)
    await user.click(screen.getByRole('switch', { name: 'Require OIDC for CI' }))
    await user.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(api.save).not.toHaveBeenCalled()
  })

  it('requiring OIDC is one click, no dialog', async () => {
    api.settings = { require_oidc: false }
    api.save.mockResolvedValue({ require_oidc: true })
    const user = userEvent.setup()
    render(<CIRequireOIDC canWrite />)
    await user.click(screen.getByRole('switch', { name: 'Require OIDC for CI' }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() => expect(api.save).toHaveBeenCalledWith({ require_oidc: true }))
  })
})
