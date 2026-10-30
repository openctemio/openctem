import { BrandLogoFull, PoweredBy } from '@/components/brand-logo'

type AuthLayoutProps = {
  children: React.ReactNode
}

export default function AuthLayout({ children }: AuthLayoutProps) {
  return (
    /*
      min-h-svh + flex column lets the page grow taller than the
      viewport when needed (e.g. team list with many entries) instead
      of clipping. The previous `grid h-svh items-center justify-center`
      vertically centered the content, which on a tall mobile screen
      pushed the logo into the middle and left big dead space top/bottom.
      Now content starts from a small top padding and grows downward,
      with `safe-area-inset-top` so it clears the iOS notch.

      sm:items-center re-enables vertical centering on tablet/desktop
      where the screen is wider/shorter and centering looks balanced.
    */
    <div className="flex min-h-svh flex-col items-stretch sm:items-center sm:justify-center px-4 py-6 sm:py-12 pt-[max(1.5rem,env(safe-area-inset-top))]">
      <div className="mx-auto flex w-full max-w-md flex-col space-y-2 sm:w-[480px]">
        <div className="mb-4 sm:mb-8 flex items-center justify-center text-foreground">
          {/* The lockup (6.5:1) is tight around the ink: h-8 on phones and h-10
              from sm up give about the width of the card title below it. */}
          <BrandLogoFull className="h-8 sm:h-10 w-auto" />
        </div>
        {children}
        <PoweredBy className="pt-4" />
      </div>
    </div>
  )
}
