/**
 * Runs in the browser before the app hydrates (Next.js file convention).
 *
 * Every same-origin state-changing fetch, Next's Server Action requests
 * included, carries the CSRF header from here on (src/lib/csrf-client.ts).
 */
import { installCsrfFetch } from '@/lib/csrf-client'

installCsrfFetch()
