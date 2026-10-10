---
name: web-change
description: Conventions for changing the web console in web/ - fix every occurrence through shared components, the shared dialog frame, i18n in en and vi, permission-aware UI, links, verification at phone and desktop width. Use for any page, component, dialog or style change under web/.
---

Read `web/CLAUDE.md` first; it points to the detailed guides in `web/.claude/`.

1. **Fix everywhere.** Before fixing a defect, `git grep` for the same markup or pattern across `web/src`.
   Fix it in the shared component or extract one and migrate every caller in the same PR. A page-only fix is
   fine only when the problem is page-specific; say so in the PR.
2. **Dialogs and sheets** use the shared frame in `web/src/components/ui/dialog.tsx`:
   `<DialogContent size="...">` with `DialogHeader`, `DialogBody` (the scrolling region) and `DialogFooter`.
   Never set `max-h-*`, `overflow-*` or `max-w-*` on the content; use `size`. The modal-layout governance
   test enforces this.
3. **Text** goes through `useTranslation()` (`@/context/i18n-provider`). Add every key to
   `src/lib/i18n/dictionaries/en.json` and `vi.json` in the same PR.
4. **Permissions:** `<Can permission={Permission.X}>` or `usePermissions()` to hide or disable actions; the API
   is the only authority, so never rely on the UI check. Module-gated pages follow the API's module state.
5. **Links and data:** import links from `@/components/link`, not `next/link` directly (the request-hygiene
   guard fails otherwise). No mock or demo data in shipped pages; use the shared loading, empty and error
   states. Lists that can grow use server pagination.
6. **Routes:** when a page moves, update every internal link and add a test that nothing references the old
   path; no redirects or aliases for renamed pages.
7. **Verify:** `npm run validate`, vitest for touched areas, then load the real page at about 390px and at
   desktop width, light and dark, and check the console. When the contract changed, run `make generate` first.
8. **Design quality:** follow `web/.claude/style-guide.md`; keep pages space-efficient and consistent with
   their siblings.
