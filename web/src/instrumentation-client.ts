/**
 * Runs in the browser before the app hydrates (Next.js file convention).
 *
 * Every same-origin state-changing fetch, Next's Server Action requests
 * included, carries the CSRF header from here on (src/lib/csrf-client.ts).
 */
import { installCsrfFetch } from '@/lib/csrf-client'
import { installPrimedFetch } from '@/lib/api/view-prime'

installCsrfFetch()
// A page view's answers serve the page's own reads (src/lib/api/view-prime.ts).
installPrimedFetch()
