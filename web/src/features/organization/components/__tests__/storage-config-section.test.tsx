import { createRef } from 'react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'

const api = vi.hoisted(() => ({ get: vi.fn(), patch: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', () => ({ useCanMutate: () => true }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import {
  StorageConfigSection,
  type StorageConfigHandle,
  type StorageFormState,
} from '../storage-config-card'

function setup(stored: Record<string, unknown>) {
  api.get.mockResolvedValue(stored)
  const ref = createRef<StorageConfigHandle>()
  const states: StorageFormState[] = []
  render(<StorageConfigSection ref={ref} onStateChange={(s) => states.push(s)} />)
  return { ref, last: () => states.at(-1) as StorageFormState }
}

describe('StorageConfigSection', () => {
  beforeEach(() => {
    api.get.mockReset()
    api.patch.mockReset()
  })

  it('has no save button of its own and reports a clean form', async () => {
    const { last } = setup({ configured: false })
    await screen.findByLabelText('Provider')
    expect(screen.queryByRole('button', { name: /save/i })).toBeNull()
    expect(last()).toEqual({ dirty: false, invalid: false, saving: false })
  })

  it('never reads the stored keys back and keeps them when the fields stay empty', async () => {
    const { ref, last } = setup({
      configured: true,
      provider: 's3',
      bucket: 'evidence',
      region: 'ap-southeast-1',
    })
    const access = (await screen.findByLabelText('Access key')) as HTMLInputElement
    const secret = screen.getByLabelText('Secret key') as HTMLInputElement
    expect(access.value).toBe('')
    expect(secret.value).toBe('')
    expect(secret.type).toBe('password')
    fireEvent.change(screen.getByLabelText('Region'), { target: { value: 'eu-west-1' } })
    await waitFor(() => expect(last().dirty).toBe(true))
    api.patch.mockResolvedValue({})
    let ok: boolean | undefined
    await act(async () => {
      ok = await ref.current?.save()
    })
    expect(ok).toBe(true)
    expect(api.patch).toHaveBeenCalledWith('/api/v1/attachments/storage-config', {
      provider: 's3',
      bucket: 'evidence',
      region: 'eu-west-1',
      endpoint: '',
      access_key: '',
      secret_key: '',
    })
    await waitFor(() => expect(last().dirty).toBe(false))
  })

  it('refuses a save without the bucket and ties the message to the field', async () => {
    const { ref, last } = setup({ configured: true, provider: 's3', bucket: 'evidence' })
    const bucket = await screen.findByLabelText('Bucket name')
    fireEvent.change(bucket, { target: { value: ' ' } })
    await waitFor(() => expect(last()).toMatchObject({ dirty: true, invalid: true }))
    let ok: boolean | undefined
    await act(async () => {
      ok = await ref.current?.save()
    })
    expect(ok).toBe(false)
    expect(api.patch).not.toHaveBeenCalled()
    expect(bucket).toHaveAttribute('aria-invalid', 'true')
    expect(bucket).toHaveAccessibleDescription('Required')
  })

  it('keeps the changes when the save fails, and Discard returns to the stored values', async () => {
    const { ref, last } = setup({ configured: true, provider: 's3', bucket: 'evidence' })
    const bucket = (await screen.findByLabelText('Bucket name')) as HTMLInputElement
    fireEvent.change(bucket, { target: { value: 'other' } })
    api.patch.mockRejectedValue(new Error('nope'))
    let ok: boolean | undefined
    await act(async () => {
      ok = await ref.current?.save()
    })
    expect(ok).toBe(false)
    expect(bucket.value).toBe('other')
    expect(last().dirty).toBe(true)
    act(() => ref.current?.discard())
    expect(bucket.value).toBe('evidence')
  })

  it('shows the load failure with Retry, never "local" as if it were stored', async () => {
    api.get.mockRejectedValue(new Error('down'))
    render(<StorageConfigSection />)
    expect(
      await screen.findByText('The file storage settings could not be loaded')
    ).toBeInTheDocument()
    expect(screen.queryByLabelText('Provider')).toBeNull()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})
