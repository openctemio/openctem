/**
 * Runs in the browser before the console hydrates (Next.js file convention):
 * every same-origin state-changing fetch carries the CSRF header
 * (src/lib/csrf-client.ts in the web app).
 */
import { installCsrfFetch } from '@/lib/csrf-client'
import { CONSOLE_CSRF_COOKIE } from '@console/lib/csrf-cookie'

installCsrfFetch(window, CONSOLE_CSRF_COOKIE)
