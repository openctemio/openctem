import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ToolHTTPPolicyFields } from '../tool-http-policy-fields'

describe('ToolHTTPPolicyFields', () => {
  it('edits the TLS switch and links the scan identification page', () => {
    const onChange = vi.fn()
    render(<ToolHTTPPolicyFields value={{ forbid_tool_insecure_tls: false }} onChange={onChange} />)
    fireEvent.click(screen.getByRole('switch'))
    expect(onChange).toHaveBeenLastCalledWith({ forbid_tool_insecure_tls: true })
    expect(screen.getByRole('link')).toHaveAttribute('href', '/settings/scanning/identification')
  })
})
