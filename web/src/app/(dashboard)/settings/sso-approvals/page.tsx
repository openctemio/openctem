'use client'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { usePermissions } from '@/lib/permissions'
import { SSOChangeApprovals } from '@/features/sso-approvals/components/sso-change-approvals'

/**
 * Settings › SSO approvals: SAML / identity-provider changes the platform
 * administrator proposed for this organization, approved or rejected by an
 * owner (RFC-022). Owners reach it from the in-app notification.
 */
export default function SSOApprovalsPage() {
  const { isOwner, isLoading } = usePermissions()
  return (
    <Main>
      <PageHeader
        title="SSO approvals"
        description="Sign-in changes proposed by the platform administrator. None takes effect until an owner approves it."
      />
      <div className="mt-5">{!isLoading && <SSOChangeApprovals canDecide={isOwner()} />}</div>
    </Main>
  )
}
