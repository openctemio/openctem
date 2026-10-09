'use client'

import { use } from 'react'
import Link from '@/components/link'
import { ChevronLeft } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ErrorState, PageHeader } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useAdminAuditLogs } from '@/features/admin-console/api/use-admin-audit'
import { AdminActivityTable } from '@/features/admin-console/components/admin-activity-table'
import { OrganizationSummary } from '@/features/admin-console/components/organization-summary'
import { useOrganization } from '@/features/admin-console/api/use-admin-organizations'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { OrganizationAuditChainPanel } from '@/features/admin-console/components/organization-audit-chain-panel'
import { OrganizationPlanPanel } from '@/features/admin-console/components/organization-plan-panel'
import { OrganizationModulesPanel } from '@/features/admin-console/components/organization-modules-panel'
import { OrganizationUsersSection } from '@/features/admin-console/components/organization-users-section'
import { SSOEnforcementCard } from '@/features/admin-console/components/sso-enforcement-card'
import { adminCan } from '@/features/admin-console/types'
import { SamlConfigForm } from '@/features/saml/components/saml-config-form'
import { IdentityProvidersPanel } from '@/features/sso/components/identity-providers-panel'
import { PendingSSOChangesNotice } from '@/features/sso-approvals/components/pending-sso-changes-notice'
import {
  AddDomainDialog,
  VerifiedDomainsList,
  useVerifiedDomains,
} from '@/features/verified-domains'

function VerifiedDomainsSection({ tenantId, canManage }: { tenantId: string; canManage: boolean }) {
  const { data, error, isLoading, mutate } = useVerifiedDomains(tenantId)
  const refresh = () => void mutate()
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div className="space-y-1.5">
          <CardTitle>Verified domains</CardTitle>
          <p className="text-sm text-muted-foreground">
            SSO auto-join only admits people whose email is at a domain the organization has proven
            it owns (DNS TXT record).
          </p>
        </div>
        {canManage && <AddDomainDialog tenantId={tenantId} onAdded={refresh} />}
      </CardHeader>
      <CardContent>
        {error ? (
          <ErrorState title="verified domains" error={error} onRetry={refresh} />
        ) : isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : (
          <VerifiedDomainsList
            tenantId={tenantId}
            domains={data ?? []}
            onChanged={refresh}
            canManage={canManage}
          />
        )}
      </CardContent>
    </Card>
  )
}

/** Every administrator action on this organization (admin audit by resource). */
function OrganizationActivity({ tenantId }: { tenantId: string }) {
  const list = useListParams({ filters: {} })
  const { data, isLoading } = useAdminAuditLogs({ page: list.page, resourceId: tenantId })
  return (
    <AdminActivityTable
      entries={data?.data ?? []}
      isLoading={isLoading}
      paging={{
        page: list.page,
        pageCount: data?.total_pages ?? 1,
        rowCount: data?.total ?? 0,
        onPageChange: list.setPage,
      }}
    />
  )
}

const TABS = ['overview', 'users', 'plan', 'sso', 'activity', 'audit-chain'] as const

export default function AdminOrganizationPage({
  params,
}: {
  params: Promise<{ tenantId: string }>
}) {
  const { tenantId } = use(params)
  const admin = useAdmin()
  // SSO decides who can sign in to the organization: super admins only.
  const canManageSSO = adminCan(admin.role, 'super_admin')
  // Adding people to an organization: operations admins and up.
  const canManageUsers = adminCan(admin.role, 'ops_admin')
  // Re-signing the organization's audit chain is irreversible: super admins only.
  const canRebaselineAuditChain = adminCan(admin.role, 'super_admin')
  const { data: org, error, isLoading, mutate } = useOrganization(tenantId)
  const refresh = () => void mutate()
  const { t } = useTranslation()
  // The tab lives in the URL, so a support link can open "SSO of org X".
  const [rawTab, setTab] = useUrlFilter('tab', 'overview')
  const tab = (TABS as readonly string[]).includes(rawTab) ? rawTab : 'overview'

  return (
    <Main>
      <Button asChild variant="ghost" size="sm" className="mb-2 -ms-2">
        <Link href="/admin/organizations">
          <ChevronLeft className="me-1 size-4" />
          {t('admin.nav.organizations', 'Organizations')}
        </Link>
      </Button>

      {error ? (
        <ErrorState title="the organization" error={error} onRetry={refresh} />
      ) : isLoading || !org ? (
        <div className="space-y-3">
          <Skeleton className="h-10 w-1/3" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : (
        <>
          <PageHeader
            title={org.name}
            description={org.description || `Organization ${org.slug}`}
          />
          <Tabs value={tab} onValueChange={setTab} className="mt-5">
            <div className="-mx-1 overflow-x-auto px-1">
              <TabsList>
                <TabsTrigger value="overview">
                  {t('admin.org.tab.overview', 'Overview')}
                </TabsTrigger>
                <TabsTrigger value="users">{t('admin.org.tab.users', 'Members')}</TabsTrigger>
                <TabsTrigger value="plan">{t('admin.org.tab.plan', 'Plan')}</TabsTrigger>
                <TabsTrigger value="sso">{t('admin.org.tab.sso', 'Single sign-on')}</TabsTrigger>
                <TabsTrigger value="activity">
                  {t('admin.org.tab.activity', 'Activity')}
                </TabsTrigger>
                <TabsTrigger value="audit-chain">
                  {t('admin.org.tab.auditChain', 'Audit chain')}
                </TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="overview" className="mt-4">
              <OrganizationSummary org={org} onOpenTab={setTab} />
            </TabsContent>

            <TabsContent value="users" className="mt-4">
              <OrganizationUsersSection
                tenantId={org.id}
                orgName={org.name}
                canManage={canManageUsers}
                canRecover={adminCan(admin.role, 'super_admin')}
                onChanged={refresh}
              />
            </TabsContent>

            <TabsContent value="plan" className="mt-4 space-y-5">
              <OrganizationPlanPanel tenantId={org.id} canManage={canManageUsers} />
              <OrganizationModulesPanel tenantId={org.id} canManage={canManageUsers} />
            </TabsContent>

            <TabsContent value="sso" className="mt-4 space-y-5">
              {!canManageSSO && (
                <p className="text-sm text-muted-foreground">
                  You can view this organization&apos;s SSO setup. Changing it requires a super
                  admin.
                </p>
              )}
              <SSOEnforcementCard org={org} canManage={canManageSSO} onChanged={refresh} />
              <PendingSSOChangesNotice tenantId={org.id} />
              {/* A section, not a Card: the SAML form is built from its own cards. */}
              <section className="space-y-1">
                <h2 className="text-base font-semibold">SAML 2.0</h2>
                <p className="text-sm text-muted-foreground">
                  Federate sign-in through a SAML identity provider (Okta, Entra ID, ADFS).
                </p>
                <SamlConfigForm
                  tenantId={org.id}
                  tenantSlug={org.slug}
                  canManage={canManageSSO}
                  onChanged={refresh}
                />
              </section>
              <IdentityProvidersPanel
                tenantId={org.id}
                tenantSlug={org.slug}
                canManage={canManageSSO}
                onChanged={refresh}
              />
              <VerifiedDomainsSection tenantId={org.id} canManage={canManageSSO} />
            </TabsContent>

            <TabsContent value="activity" className="mt-4">
              <OrganizationActivity tenantId={org.id} />
            </TabsContent>

            <TabsContent value="audit-chain" className="mt-4">
              <OrganizationAuditChainPanel
                tenantId={org.id}
                orgName={org.name}
                canRebaseline={canRebaselineAuditChain}
              />
            </TabsContent>
          </Tabs>
        </>
      )}
    </Main>
  )
}
