# Navigation coverage: no scaffold pages in the sidebar

A page in the sidebar must show data from its own domain. This page explains the
rule, the test that enforces it and how to check a page by hand.

## The rule

**"Imports a data hook" is not the same as "shows its own data."** A page is real
when it calls a hook scoped to its own domain:

```
useControlTests(...) / useSuppressions(...) / useFindingTypeStats(id, ['secret'])  -> real
useDashboardStats()  and nothing else                                              -> scaffold
```

In a security product, a chart labelled "Credential Exposures" that is really
showing organization-wide totals is worse than an empty page: it will be read as
fact. Do not add a page whose only data source is `useDashboardStats`; build the
feature first.

Pages outside the sidebar are not a problem by themselves: asset type pages are
reached from the `/assets` hub, and many feature pages are tabs or cards of a
parent that is in the sidebar (for example `/findings/approvals`,
`/settings/integrations/*`). Retired pages redirect to the real page for the same
question (`LEGACY_ORPHAN_ROUTE_REDIRECTS` in `src/config/legacy-routes.ts`).

## The test

`src/config/__tests__/sidebar-no-scaffolds.test.ts` walks every sidebar leaf to the
page file it resolves to and fails if that page's only data source is
`useDashboardStats`, or if it renders `ComingSoonPage` without a badge.

## Checking by hand

```bash
# routes and sidebar URLs
find src/app -name page.tsx | sed -E 's#^src/app/##; s#/page\.tsx$##; s#\([^)]*\)/##g; s#^#/#' \
  | sed 's#//*#/#g' | sort -u
grep -oE "url: '[^']+'" src/config/sidebar-data.ts | sed "s/url: '//; s/'//" | sort -u

# real vs scaffold, per page
grep -oE "\buse[A-Z][A-Za-z0-9]*[(<]" "$page" | sed 's/[(<]$//' | sort -u \
  | grep -vE "useState|useEffect|useMemo|useRouter|useCallback|useSearchParams|useRef|useParams|usePathname|useTenant|useDashboardStats|usePermissions|useHasPermission|useToast|useForm"
# imports useDashboardStats AND no domain hook => scaffold
# note the [(<]: useSWR<T>( is a real data source and a `\(`-only pattern misses it
```

Do not look for unreachable pages by grepping for `href`s: navigation goes through
config objects and template literals (`router.push(category.href)`,
``router.push(`/assets/${slug}`)``), so no static pass answers "is this
reachable". Sidebar membership is the only exact figure.
