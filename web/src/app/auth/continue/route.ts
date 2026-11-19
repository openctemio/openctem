/**
 * After a sign-in: decides where the person lands from their memberships
 * (features/auth/lib/sign-in-landing.ts) and sends them there.
 *
 * A Route Handler because it writes the session cookies (the account-only or
 * the organization token). It is reached by a redirect from the sign-in
 * callback, in a new request, so it reads the cookies that callback set. It
 * only selects an organization the API admits this session to, for the person
 * the cookies belong to; `next` is validated as a same-origin path.
 */

import { redirect } from 'next/navigation'
import type { NextRequest } from 'next/server'

import { landingHref } from '@/features/auth/lib/continue-href'
import { prepareLanding } from '@/features/auth/lib/sign-in-landing'

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  const landing = await prepareLanding()
  redirect(landingHref(landing, request.nextUrl.searchParams.get('next')))
}
