'use client'

import { cn } from '@/lib/utils'

import { usePasswordPolicy } from '../api/use-auth-providers'
import { describePasswordPolicy } from '../lib/password-policy'

/**
 * The password rules under a "choose a password" field, as the API reports
 * them. Renders nothing until the policy is known.
 */
export function PasswordPolicyHint({ className, id }: { className?: string; id?: string }) {
  const policy = usePasswordPolicy()
  if (!policy) return null
  return (
    <p id={id} className={cn('text-xs text-muted-foreground', className)}>
      {describePasswordPolicy(policy)} Passwords found in known breaches are refused.
    </p>
  )
}
