/**
 * Auth Refresh Route
 *
 * Handles token refresh by reading tokens from cookies
 * and sending to backend refresh endpoint.
 *
 * Flow:
 * 1. Read refresh token from cookie
 * 2. Read tenant info from tenant cookie
 * 3. Refresh through refreshSessionOnce (one API call per refresh token)
 * 4. Update cookies with new tokens
 * 5. Return new access token to client
 */

import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'

import { env } from '@/lib/env'
import { requestAccountToken } from '@/features/auth/lib/account-session'
import { devLog } from '@/lib/logger'
import { csrfRejection } from '@/lib/server-auth-cookies'
import { refreshSessionOnce } from '@/lib/server-refresh'

// Frontend cookie names (from env config)
const ACCESS_TOKEN_COOKIE = env.auth.cookieName
const REFRESH_TOKEN_COOKIE = env.auth.refreshCookieName
const TENANT_COOKIE = env.cookies.tenant
// NOTE: Permissions are NOT stored in cookies anymore (too large, > 4KB limit)
// Frontend fetches permissions via /api/v1/me/permissions API instead

interface TenantInfo {
  id: string
  slug: string
  name?: string
  role: string
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  devLog.log('[Refresh] Token refresh request received')
  // Cookie-authenticated, state-changing: same origin and the double-submit pair.
  const csrf = csrfRejection(request)
  if (csrf) return csrf
  try {
    const cookieStore = await cookies()

    // Get refresh token from cookie
    const refreshToken = cookieStore.get(REFRESH_TOKEN_COOKIE)?.value
    devLog.log('[Refresh] Refresh token cookie:', refreshToken ? 'present' : 'MISSING')
    if (!refreshToken) {
      return NextResponse.json(
        { success: false, error: { code: 'NO_REFRESH_TOKEN', message: 'No refresh token found' } },
        { status: 401 }
      )
    }

    // Get tenant info from cookie
    const tenantCookie = cookieStore.get(TENANT_COOKIE)?.value
    devLog.log('[Refresh] Tenant cookie:', tenantCookie ? 'present' : 'MISSING')
    let tenantId: string | undefined
    let existingTenantName: string | undefined

    if (tenantCookie) {
      try {
        const tenantInfo: TenantInfo = JSON.parse(tenantCookie)
        tenantId = tenantInfo.id
        existingTenantName = tenantInfo.name // Preserve existing name
        devLog.log('[Refresh] Tenant ID:', tenantId)
      } catch {
        devLog.error('[Refresh] Failed to parse tenant cookie')
      }
    }

    if (!tenantId && cookieStore.get(env.cookies.accountOnly)?.value) {
      // No organization: renew the account-only token (api RFC-141).
      const account = await requestAccountToken(refreshToken)
      if (!account.ok) {
        const status =
          account.code === 'SESSION' ? 401 : account.code === 'HAS_ORGANIZATION' ? 409 : 502
        const failed = NextResponse.json(
          {
            success: false,
            error: { code: `ACCOUNT_${account.code}`, message: 'Token refresh failed' },
          },
          { status }
        )
        if (status === 401) {
          for (const name of [ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, env.cookies.accountOnly]) {
            failed.cookies.set(name, '', {
              httpOnly: true,
              secure: process.env.SECURE_COOKIES !== 'false',
              sameSite: 'lax',
              maxAge: 0,
              path: '/',
            })
          }
        }
        return failed
      }
      const ok = NextResponse.json({
        success: true,
        data: { access_token: account.accessToken, expires_in: account.expiresIn },
      })
      const base = {
        httpOnly: true,
        secure: process.env.SECURE_COOKIES !== 'false',
        sameSite: 'lax' as const,
        path: '/',
      }
      ok.cookies.set(ACCESS_TOKEN_COOKIE, account.accessToken, {
        ...base,
        maxAge: account.expiresIn,
      })
      if (account.refreshToken) {
        ok.cookies.set(REFRESH_TOKEN_COOKIE, account.refreshToken, {
          ...base,
          maxAge: 7 * 24 * 60 * 60,
        })
      }
      return ok
    }

    if (!tenantId) {
      return NextResponse.json(
        { success: false, error: { code: 'NO_TENANT', message: 'No tenant context found' } },
        { status: 400 }
      )
    }

    // One refresh per refresh token across every route of this server:
    // concurrent and recent callers with the same token share the result.
    const result = await refreshSessionOnce(refreshToken, tenantId)

    // Handle a refused refresh
    if (!result.ok) {
      devLog.error('[Refresh] Backend returned error:', result.status, result.code)
      if (result.status === 0) {
        return NextResponse.json(
          { success: false, error: { code: 'REFRESH_FAILED', message: 'Failed to refresh token' } },
          { status: 502 }
        )
      }

      // Create error response
      const errorResponse = NextResponse.json(
        {
          success: false,
          error: {
            code: result.code || 'REFRESH_FAILED',
            message: result.message || 'Token refresh failed',
          },
        },
        { status: result.status }
      )

      // CRITICAL: Clear ALL cookies when refresh fails with 401
      // This prevents login loops caused by stale cookies.
      // MFA_ENROLLMENT_REQUIRED (403): the organization now requires two-factor
      // authentication and this user has not set it up. The session stays: the
      // cookies are kept so the person can set it up on /two-factor-setup
      // (the refresh token is not spent by a refused refresh).
      // ORGANIZATION_SUSPENDED (403): the organization was suspended by the
      // platform operator; signing in again lists it as suspended.
      if (result.status === 401 || result.code === 'ORGANIZATION_SUSPENDED') {
        devLog.log('[Refresh] Clearing ALL auth cookies due to invalid refresh token')
        for (const name of [ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE]) {
          errorResponse.cookies.set(name, '', {
            httpOnly: true,
            secure: process.env.SECURE_COOKIES !== 'false',
            sameSite: 'lax',
            maxAge: 0,
            path: '/',
          })
        }
        // Clear tenant cookie to prevent login loops
        // When user logs in again, they'll go through proper tenant selection
        errorResponse.cookies.set(TENANT_COOKIE, '', {
          httpOnly: false,
          secure: process.env.SECURE_COOKIES !== 'false',
          sameSite: 'lax',
          maxAge: 0,
          path: '/',
        })
      }

      return errorResponse
    }

    const data = {
      access_token: result.accessToken,
      expires_in: result.expiresIn,
      tenant_id: result.tenantId,
      tenant_slug: result.tenantSlug,
      role: result.role,
    }
    devLog.log('[Refresh] Backend success, new access_token:', !!data.access_token)

    // Build success response
    // NOTE: Permissions NOT included here - frontend fetches via /api/v1/me/permissions
    const clientResponse = NextResponse.json({
      success: true,
      data: {
        access_token: data.access_token,
        expires_in: data.expires_in,
        tenant_id: data.tenant_id,
        tenant_slug: data.tenant_slug,
        role: data.role,
      },
    })

    // Update access token cookie
    // WARNING: Browser cookie limit is ~4096 bytes. Large JWTs will be silently rejected!
    const tokenLength = data.access_token?.length || 0
    if (tokenLength > 4000) {
      devLog.warn(
        `[Refresh] WARNING: Token size (${tokenLength} bytes) may exceed browser cookie limit!`
      )
    }
    clientResponse.cookies.set(ACCESS_TOKEN_COOKIE, data.access_token, {
      httpOnly: true,
      secure: process.env.SECURE_COOKIES !== 'false',
      sameSite: 'lax',
      maxAge: data.expires_in || 900,
      path: '/',
    })

    // Store the rotated refresh token. The API sends it in Set-Cookie only;
    // keeping the old cookie left a revoked token and the next refresh signed
    // the user out.
    const rotated = result.refreshToken
    if (rotated) {
      clientResponse.cookies.set(REFRESH_TOKEN_COOKIE, rotated, {
        httpOnly: true,
        secure: process.env.SECURE_COOKIES !== 'false',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        path: '/',
      })
    }

    // Update tenant info cookie (preserve existing name if available)
    clientResponse.cookies.set(
      TENANT_COOKIE,
      JSON.stringify({
        id: data.tenant_id,
        slug: data.tenant_slug,
        name: existingTenantName || data.tenant_slug, // Preserve name or fallback to slug
        role: data.role,
      }),
      {
        httpOnly: false,
        secure: process.env.SECURE_COOKIES !== 'false',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      }
    )
    // NOTE: Permissions NOT stored in cookie - frontend fetches via /api/v1/me/permissions

    return clientResponse
  } catch (error) {
    console.error('Token refresh error:', error)
    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'REFRESH_FAILED',
          message: 'Failed to refresh token',
        },
      },
      { status: 500 }
    )
  }
}
