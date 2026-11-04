import type { ReactNode } from 'react'

/**
 * One way to sign in, in the Account > Security lists (connected sign-in
 * methods, organization sign-in): an icon, a name, status lines and the
 * action on the right.
 */
export function SignInMethodRow({
  icon,
  title,
  lines,
  action,
  testId,
}: {
  icon: ReactNode
  title: ReactNode
  lines?: ReactNode[]
  action?: ReactNode
  testId?: string
}) {
  return (
    <li className="flex items-center justify-between gap-4 p-4" data-testid={testId}>
      <div className="flex min-w-0 items-center gap-3">
        <span className="shrink-0 [&>svg]:h-5 [&>svg]:w-5">{icon}</span>
        <div className="min-w-0 space-y-0.5">
          <span className="font-medium">{title}</span>
          {lines?.map((line, i) => (
            <p key={i} className="text-sm text-muted-foreground">
              {line}
            </p>
          ))}
        </div>
      </div>
      {action}
    </li>
  )
}
