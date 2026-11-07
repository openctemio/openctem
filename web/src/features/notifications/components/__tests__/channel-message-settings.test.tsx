import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import { ChannelMessageSettings } from '../channel-message-settings'

const preview = vi.fn()
let refusal: Error | null = null
vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  previewNotificationMessage: (...args: unknown[]) => {
    // A plain function rejects: a vi.fn returning a rejected promise is
    // reported as an error of the test.
    if (refusal) {
      const err = refusal
      return new Promise((_, reject) => reject(err))
    }
    return preview(...args)
  },
}))

describe('ChannelMessageSettings', () => {
  beforeEach(() => {
    preview.mockReset()
    refusal = null
  })

  it('renders the API preview: headline once, labelled lines, one action', async () => {
    preview.mockResolvedValue({
      headline: 'New exposure',
      severity: 'high',
      lines: [
        { label: 'Severity', value: 'High' },
        { label: 'Asset', value: 'admin.example.com (subdomain)' },
      ],
      action_label: 'Open exposure',
      text: '',
      variables: [],
    })
    render(
      <ChannelMessageSettings
        idPrefix="t"
        detailLevel="standard"
        onDetailLevelChange={() => {}}
        template=""
        onTemplateChange={() => {}}
      />
    )
    expect(await screen.findByText('New exposure')).toBeInTheDocument()
    expect(screen.getByText('admin.example.com (subdomain)')).toBeInTheDocument()
    expect(screen.getByText('Open exposure')).toBeInTheDocument()
    expect(preview).toHaveBeenCalledWith(
      expect.objectContaining({ detail_level: 'standard', message_template: '' })
    )
  })

  it('shows the API refusal of a template with an unknown variable', async () => {
    refusal = new ApiClientError('unknown template variable: severity_emoji', 'BAD_REQUEST', 400)
    render(
      <ChannelMessageSettings
        idPrefix="t"
        detailLevel="minimal"
        onDetailLevelChange={() => {}}
        template="{severity_emoji} {title}"
        onTemplateChange={() => {}}
      />
    )
    expect(await screen.findByRole('alert')).toHaveTextContent('severity_emoji')
  })
})
