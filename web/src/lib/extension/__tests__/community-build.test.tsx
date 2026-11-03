/**
 * The default build has no extension: the `@extension/*` aliases resolve to the
 * stub, which adds nothing, and the core navigation and catalogs are exactly
 * the core's own.
 */
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'

import { extension as consoleStub } from '@extension/console'
import { messages as messagesStub } from '@extension/messages'
import { webExtension, COMMUNITY_EDITION, EXTENSION_API_VERSION } from '@/lib/extension'
import { ExtensionSlot } from '@/lib/extension/slot'
import { Overridable } from '@/lib/extension/overridable'

describe('Community build', () => {
  it('registers no extension', () => {
    expect(webExtension.edition).toBe(COMMUNITY_EDITION)
    expect(webExtension.apiVersion).toBe(EXTENSION_API_VERSION)
    expect(webExtension.navItems).toHaveLength(0)
    expect(webExtension.settingsItems).toHaveLength(0)
    expect(Object.keys(webExtension.slots)).toHaveLength(0)
    expect(Object.keys(webExtension.overrides)).toHaveLength(0)
    expect(consoleStub.navItems).toHaveLength(0)
    expect(Object.keys(messagesStub.en)).toHaveLength(0)
    expect(Object.keys(messagesStub.vi)).toHaveLength(0)
  })

  it('renders nothing in an extension slot', () => {
    const { container } = render(<ExtensionSlot id="reports.sections" />)
    expect(container.innerHTML).toBe('')
  })

  it('renders the core component where an override is allowed', () => {
    const Core = ({ className }: { className?: string }) => <p className={className}>core footer</p>
    const { getByText } = render(<Overridable id="auth.footer" fallback={Core} className="pt-4" />)
    expect(getByText('core footer')).toHaveClass('pt-4')
  })

  it('renders nothing in the SCIM settings slot', () => {
    const { container } = render(<ExtensionSlot id="settings.scim.sections" />)
    expect(container.innerHTML).toBe('')
  })
})
