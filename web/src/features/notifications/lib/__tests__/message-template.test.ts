import { describe, it, expect } from 'vitest'
import { renderMessageTemplatePreview, TEMPLATE_PRESETS } from '../message-template'

describe('renderMessageTemplatePreview', () => {
  it('links the sample finding to this console, not a fixed host', () => {
    const out = renderMessageTemplatePreview('{title} {url}', 'https://ctem.example.com')
    expect(out).toBe('SQL Injection Vulnerability Detected https://ctem.example.com/findings/123')
  })

  it('explains an empty template', () => {
    expect(renderMessageTemplatePreview('', 'https://ctem.example.com')).toBe(
      'Using default system template'
    )
  })

  it('keeps the presets the dialogs offer', () => {
    expect(TEMPLATE_PRESETS.map((p) => p.id)).toContain('custom')
  })
})
