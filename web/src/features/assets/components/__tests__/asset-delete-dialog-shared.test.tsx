import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AssetDeleteDialogShared } from '../asset-delete-dialog-shared'

function renderDialog(props: Partial<React.ComponentProps<typeof AssetDeleteDialogShared>> = {}) {
  const onConfirm = vi.fn()
  const onArchive = vi.fn()
  render(
    <AssetDeleteDialogShared
      open
      onOpenChange={vi.fn()}
      assetName="api.example.com"
      typeName="Asset"
      onConfirm={onConfirm}
      {...props}
    />
  )
  return { onConfirm, onArchive }
}

describe('AssetDeleteDialogShared', () => {
  it('names the asset and says the delete cannot be undone', () => {
    renderDialog()
    expect(screen.getByText('Delete the asset "api.example.com"?')).toBeInTheDocument()
    expect(screen.getByText(/This cannot be undone/)).toBeInTheDocument()
  })

  it('deletes only after the exact asset name is typed', async () => {
    const { onConfirm } = renderDialog()
    const del = screen.getByRole('button', { name: 'Delete' })
    expect(del).toBeDisabled()
    const input = screen.getByLabelText(/Type\s*api\.example\.com\s*to confirm/)
    await userEvent.type(input, 'api.example.co')
    expect(del).toBeDisabled()
    await userEvent.click(del)
    expect(onConfirm).not.toHaveBeenCalled()
    await userEvent.type(input, 'm')
    await userEvent.click(del)
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('offers Archive instead of a delete the server would refuse when the asset has findings', async () => {
    const onArchive = vi.fn()
    const { onConfirm } = renderDialog({ findingCount: 3, onArchive })
    expect(screen.getByText('Archive the asset "api.example.com"?')).toBeInTheDocument()
    expect(screen.getByText(/It has 3 findings, so it cannot be deleted/)).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Archive' }))
    expect(onArchive).toHaveBeenCalledTimes(1)
    expect(onConfirm).not.toHaveBeenCalled()
  })

  it('keeps the typed delete when the caller cannot archive', () => {
    renderDialog({ findingCount: 3 })
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled()
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })
})
