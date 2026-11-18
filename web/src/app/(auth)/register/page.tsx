import { Suspense } from 'react'
import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { env } from '@/lib/env'
import { legalConfig } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'
import { authProvidersSettings } from '@/lib/auth-providers-settings'
import { AuthProvidersFallback } from '@/features/auth/components/auth-providers-fallback'

import { RegisterGate } from '@/features/auth/components/register-gate'

export default async function SignUp() {
  // Check if user is already authenticated
  const cookieStore = await cookies()
  const hasAuthToken = cookieStore.get(env.auth.cookieName)?.value
  const hasRefreshToken = cookieStore.get(env.auth.refreshCookieName)?.value

  if (hasAuthToken || hasRefreshToken) {
    // User is authenticated - check if they have a tenant
    const hasTenant = cookieStore.get(env.cookies.tenant)?.value
    if (hasTenant) {
      redirect('/')
    } else {
      redirect('/welcome')
    }
  }

  const [legalRec, providers] = await Promise.all([legalSettings(), authProvidersSettings()])
  const legal = legalConfig(legalRec)

  // The gate shows the form only when open registration is on or the visitor
  // came from an invitation; otherwise "accounts are created by your admin".
  return (
    <AuthProvidersFallback providers={providers}>
      <Suspense>
        <RegisterGate termsUrl={legal.termsUrl} privacyUrl={legal.privacyUrl} />
      </Suspense>
    </AuthProvidersFallback>
  )
}
