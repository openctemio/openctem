/**
 * Message template presets for notification channels, and the preview the
 * add and edit dialogs show while a template is being written.
 */
export const TEMPLATE_PRESETS = [
  {
    id: 'default',
    name: 'Default',
    template: '',
    description: 'Use system default template',
  },
  {
    id: 'detailed',
    name: 'Detailed Report',
    template: `**{severity} Alert: {title}**

{body}

---
View details: {url}
Timestamp: {timestamp}`,
    description: 'Full details with all fields',
  },
  {
    id: 'minimal',
    name: 'Minimal Alert',
    template: `{title}
{url}`,
    description: 'Title and link only',
  },
  {
    id: 'emoji',
    name: 'With Severity Emoji',
    template: `{severity_emoji} [{severity}] {title}

{body}

{url}`,
    description: 'Includes severity emoji indicator',
  },
  {
    id: 'custom',
    name: 'Custom',
    template: '',
    description: 'Write your own template',
  },
]

/**
 * Render `template` with sample values. The sample finding link points at
 * this console (`origin`), the host real notifications link to.
 */
export function renderMessageTemplatePreview(template: string, origin: string): string {
  if (!template) return 'Using default system template'

  const sampleData: Record<string, string> = {
    title: 'SQL Injection Vulnerability Detected',
    severity: 'CRITICAL',
    severity_emoji: '\u{1F6A8}',
    body: 'A potential SQL injection vulnerability was found in the login endpoint.',
    url: `${origin}/findings/123`,
    timestamp: new Date().toLocaleString(),
  }

  let preview = template
  Object.entries(sampleData).forEach(([key, value]) => {
    preview = preview.replace(new RegExp(`\\{${key}\\}`, 'g'), value)
  })
  return preview
}
