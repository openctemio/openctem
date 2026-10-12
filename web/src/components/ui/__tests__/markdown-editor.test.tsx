import { describe, expect, it, vi } from 'vitest'
import * as React from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MarkdownEditor, type MarkdownUploadHandler } from '../markdown-editor'

vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))
vi.mock('next/dynamic', () => ({
  default: () =>
    function Preview({ source }: { source: string }) {
      return <div data-testid="md-preview">{source}</div>
    },
}))

function Harness(props: {
  initial?: string
  onUploadFile?: MarkdownUploadHandler
  maxLength?: number
}) {
  const [value, setValue] = React.useState(props.initial ?? '')
  return (
    <>
      <MarkdownEditor
        value={value}
        onChange={setValue}
        aria-label="Body"
        onUploadFile={props.onUploadFile}
        maxLength={props.maxLength}
      />
      <output data-testid="value">{value}</output>
    </>
  )
}

const value = () => screen.getByTestId('value').textContent

describe('MarkdownEditor', () => {
  it('formats the selection from the toolbar and from the keyboard', () => {
    render(<Harness initial="hello" />)
    const ta = screen.getByLabelText('Body') as HTMLTextAreaElement
    ta.setSelectionRange(0, 5)
    fireEvent.click(screen.getByRole('button', { name: 'Bold' }))
    expect(value()).toBe('**hello**')
    ta.setSelectionRange(2, 7)
    fireEvent.keyDown(ta, { key: 'i', ctrlKey: true })
    expect(value()).toBe('**_hello_**')
  })

  it('keeps every command reachable on one toolbar row', () => {
    render(<Harness />)
    // Without a measured width all buttons show; with one, the rest go to "More".
    expect(screen.getAllByRole('toolbar')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Horizontal rule' })).toBeTruthy()
  })

  it('switches to a preview of the text', () => {
    render(<Harness initial="# Title" />)
    fireEvent.click(screen.getByRole('tab', { name: 'Preview' }))
    expect(screen.getByTestId('md-preview').textContent).toBe('# Title')
    fireEvent.click(screen.getByRole('tab', { name: 'Write' }))
    expect(screen.getByLabelText('Body')).toBeTruthy()
  })

  it('uploads a pasted file and replaces the placeholder with its markdown', async () => {
    let finish: (md: string) => void = () => {}
    const upload = vi.fn<MarkdownUploadHandler>((_file, onProgress) => {
      onProgress(0.5)
      return new Promise((resolve) => (finish = resolve))
    })
    render(<Harness initial="see" onUploadFile={upload} />)
    const ta = screen.getByLabelText('Body') as HTMLTextAreaElement
    ta.setSelectionRange(3, 3)
    const file = new File(['x'], 'shot.png', { type: 'image/png' })
    fireEvent.paste(ta, { clipboardData: { files: [file] } })
    expect(upload).toHaveBeenCalledWith(file, expect.any(Function))
    expect(value()).toContain('Uploading shot.png')
    expect(screen.getByText('50%')).toBeTruthy()
    await act(async () => finish('![shot.png](/api/v1/attachments/a1)'))
    await waitFor(() => expect(value()).toBe('see\n![shot.png](/api/v1/attachments/a1)\n'))
    expect(screen.queryByText('50%')).toBeNull()
  })

  it('removes the placeholder when an upload fails', async () => {
    const upload = vi.fn<MarkdownUploadHandler>(() => Promise.reject(new Error('nope')))
    render(<Harness onUploadFile={upload} />)
    const ta = screen.getByLabelText('Body')
    fireEvent.paste(ta, {
      clipboardData: { files: [new File(['x'], 'a.png', { type: 'image/png' })] },
    })
    await waitFor(() => expect(value()).toBe(''))
  })

  it('ignores pasted files when uploads are off', () => {
    render(<Harness />)
    const ta = screen.getByLabelText('Body')
    fireEvent.paste(ta, { clipboardData: { files: [new File(['x'], 'a.png')] } })
    expect(value()).toBe('')
  })

  it('shows a counter near the length limit', () => {
    render(<Harness initial={'x'.repeat(9)} maxLength={10} />)
    expect(screen.getByText('9 / 10 characters')).toBeTruthy()
  })
})
