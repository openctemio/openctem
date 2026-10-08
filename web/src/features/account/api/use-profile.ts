/**
 * Profile API Hooks
 *
 * React hooks for managing user profile
 */

import useSWR from 'swr'
import { get, put } from '@/lib/api/client'
import { userEndpoints } from '@/lib/api/endpoints'
import type { UserProfile, UpdateProfileInput } from '../types/account.types'
import { useCallback, useState } from 'react'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { SWR_REFERENCE } from '@/lib/swr-config'

// ============================================
// FETCH PROFILE
// ============================================

/**
 * Hook to fetch current user's profile
 */
export function useProfile() {
  // Inside the app shell the session bootstrap carries the profile and seeds
  // this key (context/bootstrap-session.ts): wait for it, then read the cache.
  const bootstrapPending = useBootstrapPending()
  const { data, error, isLoading, mutate } = useSWR<UserProfile>(
    bootstrapPending ? null : userEndpoints.me(),
    (url: string) => get<UserProfile>(url),
    {
      ...SWR_REFERENCE,
      revalidateOnFocus: false,
    }
  )

  return {
    profile: data,
    isLoading,
    isError: !!error,
    error,
    mutate,
  }
}

// ============================================
// UPDATE PROFILE
// ============================================

/**
 * Hook to update user profile
 */
export function useUpdateProfile() {
  const [isUpdating, setIsUpdating] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  const updateProfile = useCallback(
    async (input: UpdateProfileInput): Promise<UserProfile | null> => {
      setIsUpdating(true)
      setError(null)

      try {
        const result = await put<UserProfile>(userEndpoints.updateMe(), input)
        return result
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Failed to update profile')
        setError(error)
        throw error
      } finally {
        setIsUpdating(false)
      }
    },
    []
  )

  return {
    updateProfile,
    isUpdating,
    error,
  }
}

// ============================================
// AVATAR
// ============================================
