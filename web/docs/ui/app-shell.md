# App shell

The dashboard shell is flat: the sidebar on the left, a top bar, and the page
content filling the rest of the viewport. The content area is not a floating
card. It has no outer margin, border, radius or shadow, and its background is
the page background token.

## How the areas are separated

One 1px border token per edge, never a second cue next to it:

- The sidebar is separated from the content by its `border-sidebar-border`
  end border. Both sit on the same background, so there is no tint difference.
- The top bar is separated by a 1px bottom border (`border-border`). It has no
  shadow, also while the page scrolls.
- Shadows are reserved for overlays (menus, popovers, dialogs, sheets).

## Spacing

`<Main>` pads the page 16px on a phone and 24px from the `sm` breakpoint up.
The top bar uses the same horizontal padding so the page title lines up with the
bar's controls. A bar that spans the content width (the sticky action bar in the
pentest finding editor) uses the same negative margins as `<Main>`'s padding.

## Layout variant

The shell always uses the `sidebar` variant. A `layout_variant` cookie holding
`inset` or `floating` from an earlier version is ignored. `SidebarInset` carries
no frame classes of its own.

## Check

`web/e2e/specs/26-flat-shell.spec.ts` asserts the content area has no margin,
radius, border or shadow, ends at the viewport edges and uses the page
background, on `/` and `/findings` at 1440 and 390 wide in both themes, and
attaches a screenshot of each.
