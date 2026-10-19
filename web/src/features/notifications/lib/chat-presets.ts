/**
 * Chat presets that reuse the Slack-format delivery: the server sends the same
 * payload, only the webhook URL differs. The preset is a UI concept; what is
 * stored is a `slack` channel.
 */

export type ChatPresetId = 'mattermost' | 'discord'

/**
 * Returns the URL to store for a preset. Discord accepts the Slack payload only
 * on the `/slack` variant of its webhook URL, so it is appended when missing.
 * Any other URL is returned trimmed and otherwise unchanged; the server still
 * validates it (https, no private or metadata hosts).
 */
export function normalizePresetWebhookUrl(preset: string, raw: string): string {
  const value = raw.trim()
  if (preset !== 'discord') return value
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return value
  }
  const path = url.pathname.replace(/\/+$/, '')
  url.pathname = path.endsWith('/slack') ? path : `${path}/slack`
  return url.toString()
}
