/**
 * The account area's tab row on a phone: the open page's tab is scrolled into
 * view with the shared tab-strip behaviour, so "Organizations" is never cut at
 * the edge, and an edge with hidden tabs fades.
 */
import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('next/navigation', () => ({ usePathname: () => '/account/organizations' }))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock('@/components/brand-logo', () => ({ BrandMark: () => null, usesBuiltInLogo: () => false }))
vi.mock('@/assets/logo', () => ({ LogoFull: () => null }))
vi.mock('@/components/layout', () => ({
  MainRegion: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/components/skip-to-main', () => ({ SkipToMain: () => null }))
vi.mock('@/components/step-up-dialog', () => ({ StepUpDialogHost: () => null }))
vi.mock('@/components/theme-switch', () => ({ ThemeSwitch: () => null }))
vi.mock('@/context/brand-provider', () => ({ useBrand: () => ({ shortName: 'X' }) }))
vi.mock('@/context/account-space-provider', () => ({
  AccountSpaceProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
vi.mock('../account-sign-out', () => ({ AccountSignOut: () => null }))
vi.mock('../ownership-invitation-banner', () => ({ OwnershipInvitationBanner: () => null }))

import { AccountShell } from '../account-shell'

afterEach(() => {
  vi.restoreAllMocks()
  Reflect.deleteProperty(Element.prototype, 'scrollBy')
})

describe('AccountShell tab row', () => {
  it('scrolls the open page tab into view when it sits past the edge', () => {
    const scrollBy = vi.fn()
    const nav = () => screen.getByRole('navigation', { name: 'Your account' })
    Element.prototype.scrollBy = ((o: ScrollToOptions) => scrollBy(o.left ?? 0)) as never
    vi.spyOn(Element.prototype, 'clientWidth', 'get').mockReturnValue(358)
    vi.spyOn(Element.prototype, 'scrollWidth', 'get').mockReturnValue(420)
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: Element
    ) {
      const active = this.getAttribute('aria-current') === 'page'
      const left = active ? 300 : 0
      const right = active ? 420 : 358
      return {
        left,
        right,
        width: right - left,
        top: 0,
        bottom: 30,
        height: 30,
        x: left,
        y: 0,
      } as DOMRect
    })
    render(
      <AccountShell>
        <p>page</p>
      </AccountShell>
    )
    expect(nav()).toBeInTheDocument()
    expect(scrollBy).toHaveBeenCalled()
    expect(scrollBy.mock.calls[0][0]).toBeGreaterThan(0)
    expect(nav().dataset.fadeEnd).toBe('true')
  })
})
