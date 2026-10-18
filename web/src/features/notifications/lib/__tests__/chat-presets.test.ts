import { describe, expect, it } from 'vitest'
import { normalizePresetWebhookUrl } from '../chat-presets'

describe('normalizePresetWebhookUrl', () => {
  it('adds /slack to a Discord webhook URL', () => {
    expect(normalizePresetWebhookUrl('discord', 'https://discord.com/api/webhooks/1/abc')).toBe(
      'https://discord.com/api/webhooks/1/abc/slack'
    )
  })

  it('keeps an existing /slack suffix and the query string', () => {
    expect(
      normalizePresetWebhookUrl('discord', ' https://discord.com/api/webhooks/1/abc/slack/ ')
    ).toBe('https://discord.com/api/webhooks/1/abc/slack')
    expect(
      normalizePresetWebhookUrl('discord', 'https://discord.com/api/webhooks/1/abc?wait=true')
    ).toBe('https://discord.com/api/webhooks/1/abc/slack?wait=true')
  })

  it('leaves Mattermost and unparsable values alone', () => {
    expect(normalizePresetWebhookUrl('mattermost', ' https://chat.example.com/hooks/xyz ')).toBe(
      'https://chat.example.com/hooks/xyz'
    )
    expect(normalizePresetWebhookUrl('discord', 'not a url')).toBe('not a url')
  })
})
