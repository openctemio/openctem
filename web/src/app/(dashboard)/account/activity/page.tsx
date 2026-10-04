'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  History,
  Key,
  User,
  Shield,
  Users,
  Building,
  Mail,
  Settings,
  ChevronLeft,
  ChevronRight,
  type LucideIcon,
} from 'lucide-react'
import { formatRelative, formatDateSafe } from '@/lib/format-date'
import { useUser } from '@/stores/auth-store'
import { EmptyState } from '@/features/shared'
import { useAccountActivity } from '@/features/account'
import {
  getActionCategory,
  formatAction,
  RESULT_DISPLAY,
} from '@/features/organization/types/audit.types'

// Icon per action category (action looks like "auth.login", "user.updated", …)
const CATEGORY_ICONS: Record<string, LucideIcon> = {
  auth: Key,
  user: User,
  member: Users,
  invitation: Mail,
  tenant: Building,
  settings: Settings,
  permission: Shield,
  other: History,
}

const CATEGORY_COLORS: Record<string, string> = {
  auth: 'bg-green-500/10 text-green-500',
  user: 'bg-blue-500/10 text-blue-500',
  member: 'bg-purple-500/10 text-purple-500',
  invitation: 'bg-cyan-500/10 text-cyan-500',
  tenant: 'bg-indigo-500/10 text-indigo-500',
  settings: 'bg-yellow-500/10 text-yellow-500',
  permission: 'bg-orange-500/10 text-orange-500',
  other: 'bg-muted text-muted-foreground',
}

const PER_PAGE = 10

export default function ActivityPage() {
  const user = useUser()
  const [page, setPage] = useState(1)

  // Paged on the server (the user-activity endpoint has no category filter,
  // so the old browser-side "type" filter is gone with the browser paging).
  const { activities, total, totalPages, isLoading } = useAccountActivity(
    user?.id,
    page,
    PER_PAGE
  )

  return (
    <div className="grid gap-6">
      {/* Header with Filter */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <History className="h-5 w-5" />
                Activity Log
              </CardTitle>
              <CardDescription>
                View your recent account activity and security events
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-20 w-full" />
              ))}
            </div>
          ) : activities.length === 0 ? (
            <EmptyState icon={History} title="No activity found" card={false} />
          ) : (
            <div className="space-y-4">
              {activities.map((activity) => {
                const category = getActionCategory(activity.action)
                const Icon = CATEGORY_ICONS[category] ?? History
                const colorClass = CATEGORY_COLORS[category] ?? CATEGORY_COLORS.other
                const result = RESULT_DISPLAY[activity.result]

                return (
                  <div
                    key={activity.id}
                    className="flex items-start gap-4 p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div
                      className={`h-10 w-10 rounded-full flex items-center justify-center ${colorClass}`}
                    >
                      <Icon className="h-5 w-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="font-medium">{formatAction(activity.action)}</p>
                        {result && (
                          <Badge className={`${result.bgColor} ${result.color} border-0 text-xs`}>
                            {result.label}
                          </Badge>
                        )}
                      </div>
                      {activity.message && (
                        <p className="text-sm text-muted-foreground mt-0.5">{activity.message}</p>
                      )}
                      <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                        {activity.actor_ip && <span>{activity.actor_ip}</span>}
                        {activity.actor_ip && <span>•</span>}
                        <span title={formatDateSafe(activity.timestamp, 'PPpp')}>
                          {formatRelative(activity.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-6">
              <p className="text-sm text-muted-foreground">
                Showing {(page - 1) * PER_PAGE + 1} to {Math.min(page * PER_PAGE, total)} of{' '}
                {total} activities
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(page - 1)}
                  disabled={page === 1}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-sm">
                  Page {page} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(page + 1)}
                  disabled={page === totalPages}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Security Notice */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-start gap-4">
            <div className="h-10 w-10 rounded-full bg-blue-500/10 flex items-center justify-center flex-shrink-0">
              <Shield className="h-5 w-5 text-blue-500" />
            </div>
            <div>
              <p className="font-medium">Security Tip</p>
              <p className="text-sm text-muted-foreground mt-1">
                Review your activity regularly. Sign-ins are not listed here yet; your active
                sessions are under Security. If you see anything you do not recognise, change
                your password and sign out your other sessions.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
