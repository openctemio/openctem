'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTenant } from '@/context/tenant-provider'
import { useDataScopePolicy } from '@/features/organization/api/use-data-scope-policy'

const DISMISS_KEY = 'see-everything-banner-dismissed'

/**
 * Tells owners and admins that their organization still shows every asset to
 * members without a team, a mode that is being retired (owner decision D2),
 * and links to the setting with the list of members who would be affected.
 * Owners and admins only (the policy hook fetches nothing for anyone else);
 * dismissable for the browser session.
 */
export function SeeEverythingBanner() {
  const { currentTenant } = useTenant()
  const { policy } = useDataScopePolicy(currentTenant?.id)
  const [dismissed, setDismissed] = useState(true)

  useEffect(() => {
    try {
      setDismissed(sessionStorage.getItem(DISMISS_KEY) === currentTenant?.id)
    } catch {
      setDismissed(false)
    }
  }, [currentTenant?.id])

  if (policy !== 'everything' || dismissed) return null

  const dismiss = () => {
    setDismissed(true)
    try {
      if (currentTenant?.id) sessionStorage.setItem(DISMISS_KEY, currentTenant.id)
    } catch {
      // Storage unavailable: dismissed for this page only.
    }
  }

  return (
    <div
      role="status"
      className="flex items-center gap-3 border-b border-warning/40 bg-warning/10 px-4 py-2 text-sm text-foreground"
    >
      <p className="flex-1">
        Members who are in no team see every asset in this organization. This mode is being retired.{' '}
        <Link href="/settings/teams" className="font-medium underline underline-offset-2">
          Review who would be affected
        </Link>
      </p>
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7"
        onClick={dismiss}
        aria-label="Dismiss for this session"
      >
        <X className="h-4 w-4" />
      </Button>
    </div>
  )
}
