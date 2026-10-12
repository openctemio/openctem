import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ToolHTTPPolicyFields, toolUserAgentError } from '../tool-http-policy-fields'

describe('ToolHTTPPolicyFields', () => {
  it('edits the user agent and the TLS switch', () => {
    const onChange = vi.fn()
    render(
      <ToolHTTPPolicyFields
        value={{ tool_http_user_agent: '', forbid_tool_insecure_tls: false }}
        onChange={onChange}
      />
    )
    fireEvent.change(screen.getByLabelText('User-Agent of scan tools'), {
      target: { value: 'corp-scan' },
    })
    expect(onChange).toHaveBeenLastCalledWith({
      tool_http_user_agent: 'corp-scan',
      forbid_tool_insecure_tls: false,
    })
    fireEvent.click(screen.getByRole('switch'))
    expect(onChange).toHaveBeenLastCalledWith({
      tool_http_user_agent: '',
      forbid_tool_insecure_tls: true,
    })
  })

  it('shows why a user agent is refused', () => {
    render(
      <ToolHTTPPolicyFields
        value={{ tool_http_user_agent: 'scané', forbid_tool_insecure_tls: false }}
        onChange={() => {}}
      />
    )
    expect(screen.getByText('Use printable ASCII characters only.')).toBeInTheDocument()
  })

  it('validates like the API', () => {
    expect(toolUserAgentError('acme-scan (+soc@acme.example)')).toBeNull()
    expect(toolUserAgentError('a'.repeat(257))).toBe('At most 256 characters.')
    expect(toolUserAgentError('a\nb')).toBe('Use printable ASCII characters only.')
  })
})
