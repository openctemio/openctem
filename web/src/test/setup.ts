/**
 * Vitest Setup File
 *
 * Global test setup and configuration
 * Runs before all test files
 */

import '@testing-library/jest-dom'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// ============================================
// CLEANUP
// ============================================

// Cleanup after each test
afterEach(() => {
  cleanup()
})

// ============================================
// GLOBAL MOCKS
// ============================================

// Mock Next.js router
vi.mock('next/navigation', () => ({
  useRouter: vi.fn(() => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
  })),
  usePathname: vi.fn(() => '/'),
  useSearchParams: vi.fn(() => new URLSearchParams()),
  useParams: vi.fn(() => ({})),
}))

// Mock Next.js cookies
vi.mock('next/headers', () => ({
  cookies: vi.fn(() => ({
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    has: vi.fn(),
    getAll: vi.fn(() => []),
  })),
}))

// ============================================
// WEB STORAGE (Node >= 25)
// ============================================

// Node 25+ has its own Web Storage globals. Without --localstorage-file, its
// `localStorage` getter returns undefined, and because the global already
// exists, Vitest does not copy jsdom's working Storage over it. So
// `window.localStorage` is undefined in tests on the Node we ship (node:26,
// see web/.nvmrc). Point both globals back at the jsdom window's Storage.
// This is a no-op on older Node, where jsdom's storage is already in place.
{
  const dom = (globalThis as { jsdom?: { window: Window } }).jsdom
  for (const name of ['localStorage', 'sessionStorage'] as const) {
    let current: unknown
    try {
      current = globalThis[name]
    } catch {
      current = undefined
    }
    if (dom && typeof (current as Storage | undefined)?.setItem !== 'function') {
      const storage = dom.window[name]
      Object.defineProperty(globalThis, name, {
        configurable: true,
        enumerable: true,
        get: () => storage,
      })
    }
  }
}

// Pointer capture: jsdom has none. Vaul (the phone DetailSheet) captures the
// pointer on every press inside a drawer.
if (typeof Element !== 'undefined' && !Element.prototype.setPointerCapture) {
  Element.prototype.setPointerCapture = () => {}
  Element.prototype.releasePointerCapture = () => {}
  Element.prototype.hasPointerCapture = () => false
}
// Vaul reads `getComputedStyle(el).transform || webkitTransform || mozTransform`
// as a string; jsdom leaves all three empty or undefined (a browser says
// `none`). Answer on the last, non-standard one so real values still win.
if (
  typeof CSSStyleDeclaration !== 'undefined' &&
  !('mozTransform' in CSSStyleDeclaration.prototype)
) {
  Object.defineProperty(CSSStyleDeclaration.prototype, 'mozTransform', {
    configurable: true,
    get() {
      return 'none'
    },
  })
}

// ============================================
// ENVIRONMENT SETUP
// ============================================

// Set environment variables for tests
// Note: NODE_ENV is automatically set to 'test' by Vitest
if (!process.env.NEXT_PUBLIC_API_URL) {
  process.env.NEXT_PUBLIC_API_URL = 'http://localhost:8000'
}
if (!process.env.NEXT_PUBLIC_APP_URL) {
  process.env.NEXT_PUBLIC_APP_URL = 'http://localhost:3000'
}

// ============================================
// CONSOLE CONFIGURATION
// ============================================

// Suppress console output in tests (optional)
// Uncomment to reduce noise in test output
// global.console = {
//   ...console,
//   log: vi.fn(),
//   debug: vi.fn(),
//   info: vi.fn(),
//   warn: vi.fn(),
//   error: vi.fn(),
// }
