import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AdminApiError } from '../api/admin-client'
import { importContentPack, uploadContentPack } from '../api/use-content-packs'
import { AddContentPackDialog, contentPackFormProblem } from '../components/add-content-pack-dialog'
import { stepUpErrorMessage } from '../components/admin-confirm-dialog'
import { asLintReport } from '../components/content-lint-report'

vi.mock('../api/use-content-packs', async (orig) => ({
  ...(await orig<typeof import('../api/use-content-packs')>()),
  uploadContentPack: vi.fn(),
  importContentPack: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const t = (_k: string, fallback: string) => fallback
const DIGEST = 'sha256:' + 'a'.repeat(64)

describe('contentPackFormProblem', () => {
  const ok = {
    mode: 'import' as const,
    name: 'nuclei-core',
    version: '10.2.4',
    kind: 'nuclei-templates',
    url: 'https://example.test/p.tgz',
    digest: DIGEST,
  }

  it('accepts a valid import and refuses each bad field', () => {
    expect(contentPackFormProblem(ok)).toBeNull()
    expect(contentPackFormProblem({ ...ok, name: 'Bad Name' })).toMatch(/Name/)
    expect(contentPackFormProblem({ ...ok, version: '-1' })).toMatch(/Version/)
    expect(contentPackFormProblem({ ...ok, kind: 'K' })).toMatch(/Kind/)
    expect(contentPackFormProblem({ ...ok, url: 'http://example.test/p.tgz' })).toMatch(/https/)
    expect(contentPackFormProblem({ ...ok, digest: 'sha256:ABC' })).toMatch(/Digest/)
    expect(contentPackFormProblem({ ...ok, kind: 'x-acme/rules' })).toBeNull()
  })

  it('an upload needs a file', () => {
    expect(contentPackFormProblem({ ...ok, mode: 'upload', file: null })).toMatch(/archive/)
  })
})

describe('asLintReport', () => {
  it('reads a report from error details, nested or not', () => {
    expect(asLintReport({ lint: { files: 3, errors: [] } })?.files).toBe(3)
    expect(asLintReport({ secrets: [] })).not.toBeNull()
    expect(asLintReport({ other: 1 })).toBeNull()
    expect(asLintReport(null)).toBeNull()
  })
})

describe('stepUpErrorMessage', () => {
  it('names a missing code and a refused role; otherwise the API message', () => {
    expect(stepUpErrorMessage(new AdminApiError('x', 403, 'STEP_UP_REQUIRED'), t)).toMatch(
      /fresh code/
    )
    expect(stepUpErrorMessage(new AdminApiError('Invalid or already used code', 401), t)).toBe(
      'Invalid or already used code'
    )
    expect(stepUpErrorMessage(new AdminApiError('x', 403, 'FORBIDDEN'), t)).toMatch(/super admin/)
    expect(stepUpErrorMessage(new AdminApiError('reason is required', 400), t)).toBe(
      'reason is required'
    )
    expect(stepUpErrorMessage(new Error('boom'), t)).toMatch(/failed/)
  })
})

describe('AddContentPackDialog', () => {
  beforeEach(() => vi.clearAllMocks())

  async function fillImport(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole('button', { name: 'Add pack' }))
    await user.click(screen.getByRole('tab', { name: 'Import from a URL' }))
    await user.type(screen.getByLabelText('Name'), 'nuclei-core')
    await user.type(screen.getByLabelText('Version'), '10.2.4')
    await user.type(screen.getByLabelText('Release URL (https)'), 'https://example.test/p.tgz')
    await user.type(screen.getByLabelText('Expected digest'), DIGEST)
  }

  it('needs a reason and a six-digit code before it sends', async () => {
    const user = userEvent.setup()
    render(<AddContentPackDialog onAdded={vi.fn()} />)
    await fillImport(user)
    const send = screen.getByRole('button', { name: 'Import and sign' })
    expect(send).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'monthly template refresh')
    expect(send).toBeDisabled()
    await user.type(screen.getByLabelText('Code from your authenticator'), '12ab3456')
    expect(screen.getByLabelText('Code from your authenticator')).toHaveValue('123456')
    expect(send).toBeEnabled()
  })

  it('sends the reason and code with an import', async () => {
    const user = userEvent.setup()
    const onAdded = vi.fn()
    vi.mocked(importContentPack).mockResolvedValue({ id: 'p1', lint: { excluded: 0 } })
    render(<AddContentPackDialog onAdded={onAdded} />)
    await fillImport(user)
    await user.type(screen.getByLabelText('Reason'), 'monthly template refresh')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Import and sign' }))
    await waitFor(() => expect(onAdded).toHaveBeenCalled())
    expect(importContentPack).toHaveBeenCalledWith({
      name: 'nuclei-core',
      version: '10.2.4',
      kind: 'nuclei-templates',
      url: 'https://example.test/p.tgz',
      digest: DIGEST,
      acknowledge_secrets: false,
      reason: 'monthly template refresh',
      totp_code: '123456',
    })
  })

  it('suspected secrets show the report and need an acknowledgement and a new code', async () => {
    const user = userEvent.setup()
    vi.mocked(importContentPack)
      .mockRejectedValueOnce(
        new AdminApiError('suspected secrets', 422, 'CONTENT_SECRETS_FOUND', {
          lint: {
            files: 4,
            items: 4,
            secrets: [{ path: 'a/key.yaml', code: 'aws-key', message: 'looks like an AWS key' }],
          },
        })
      )
      .mockResolvedValueOnce({ id: 'p1' })
    render(<AddContentPackDialog onAdded={vi.fn()} />)
    await fillImport(user)
    await user.type(screen.getByLabelText('Reason'), 'monthly template refresh')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Import and sign' }))

    expect(await screen.findByText('a/key.yaml')).toBeInTheDocument()
    const again = screen.getByRole('button', { name: 'Send again with acknowledgement' })
    // The used code is cleared and the secrets are not acknowledged yet.
    expect(screen.getByLabelText('Code from your authenticator')).toHaveValue('')
    expect(again).toBeDisabled()
    await user.click(screen.getByRole('checkbox'))
    await user.type(screen.getByLabelText('Code from your authenticator'), '654321')
    expect(again).toBeEnabled()
    await user.click(again)
    await waitFor(() => expect(importContentPack).toHaveBeenCalledTimes(2))
    expect(vi.mocked(importContentPack).mock.calls[1][0]).toMatchObject({
      acknowledge_secrets: true,
      totp_code: '654321',
    })
  })

  it('sends the reason and code as upload form fields', async () => {
    const user = userEvent.setup()
    vi.mocked(uploadContentPack).mockResolvedValue({ id: 'p1' })
    render(<AddContentPackDialog onAdded={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Add pack' }))
    await user.type(screen.getByLabelText('Name'), 'nuclei-core')
    await user.type(screen.getByLabelText('Version'), '10.2.4')
    const archive = new File([new Uint8Array([0x1f, 0x8b])], 'p.tgz', { type: 'application/gzip' })
    await user.upload(screen.getByLabelText(/Archive/), archive)
    await user.type(screen.getByLabelText('Reason'), 'monthly template refresh')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Upload and sign' }))
    await waitFor(() => expect(uploadContentPack).toHaveBeenCalled())
    expect(vi.mocked(uploadContentPack).mock.calls[0][0]).toMatchObject({
      archive,
      reason: 'monthly template refresh',
      totpCode: '123456',
      acknowledgeSecrets: false,
    })
  })

  it('a rejected code shows the API message and clears the code', async () => {
    const user = userEvent.setup()
    vi.mocked(importContentPack).mockRejectedValue(
      new AdminApiError('Invalid or already used code', 401)
    )
    render(<AddContentPackDialog onAdded={vi.fn()} />)
    await fillImport(user)
    await user.type(screen.getByLabelText('Reason'), 'monthly template refresh')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Import and sign' }))
    expect(await screen.findByText('Invalid or already used code')).toBeInTheDocument()
    expect(screen.getByLabelText('Code from your authenticator')).toHaveValue('')
  })
})
