# One shared kit for the tenant app and the platform console

Both apps import their UI from `web/src` (`@/features/shared`, `@/components/ui`, `@/components`). The
console has no kit of its own: a pattern that both apps show is one component, and every page uses it. A
console-only wrapper exists only where the console adds a security step (a reason and step-up, elevation).

| Pattern                    | Component                                                                                                                                                                                                                       | Notes                                                                                                                   |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Page frame and header      | `Main` > `PageStack` > `PageHeader`                                                                                                                                                                                             | one h1; actions in the header are neutral                                                                               |
| List title row             | `ListTitleRow`, `ListCount`, `ListModified`, `ListViewChanged`                                                                                                                                                                  | the count once per list, as a pill (`data-slot="list-count"`); a changed view shows Modified, Save view, Reset after it |
| List toolbar               | `ListToolbar`, `ListSearch`, `FilterSelect`                                                                                                                                                                                     | filters live in the URL (`useListParams`)                                                                               |
| Tables                     | `DataTable` (`@/features/shared/components/data-table`)                                                                                                                                                                         | server mode, `emptyMessage`, `mobileCards`                                                                              |
| The state of a list's rows | `FilterSelect` (one value always chosen: `clearable={false}`) or the filter chips                                                                                                                                               | never `Tabs` without panels; a view mode is `ViewSwitcher`                                                              |
| Tabs                       | `Tabs` + `TabsContent` for panels in a page; `SectionTabs` / `GatedSectionTabs` for routes                                                                                                                                      | `TabsCount` for counts                                                                                                  |
| Settings                   | a `Card` per group, `SettingsSaveBar` (sticky, dirty guard, Ctrl+S), `SettingsSection` for heading rows                                                                                                                         | console: the bar's Save opens the reason and code dialog                                                                |
| Confirmations              | `ConfirmDialog` (`preview` for what changes, `reason` when it is recorded); console protected writes `AdminConfirmDialog` / `ReasonConfirmDialog`; typed confirmation via `typeToConfirm`; held requests `AwaitingApprovalBand` | `Dialog` is for create and edit forms                                                                                   |
| Destructive actions        | `DangerZone` + `DangerZoneItem` at the end of a page or overview                                                                                                                                                                | the header keeps neutral actions                                                                                        |
| Empty, loading, error      | `EmptyState`, `Skeleton`, `ErrorState`, `NoAccessState`; console read-only `RoleRequiredNotice`                                                                                                                                 |                                                                                                                         |
| States                     | computed state `TonePill`; workflow status `StatusChip`; `Badge` only for counts and tags                                                                                                                                       | text and icon, never colour alone                                                                                       |
| Numbers                    | `MetricStrip`                                                                                                                                                                                                                   | only numbers that open a filtered view                                                                                  |
| Trends and changes         | `Sparkline` and `Delta` (`components/ui`)                                                                                                                                                                                       | one image with a text summary; tone is outcome, not direction                                                           |
| Detail sheet               | `DetailSheet`                                                                                                                                                                                                                   |                                                                                                                         |

The console's eslint rule (`eslint.config.mjs`, "One shared component per pattern") refuses a raw
`@/components/ui/table`, a raw `<table>`, `@/components/ui/alert-dialog` and `Tabs` without `TabsContent` in
console pages and components. Files that predate it are listed in `CONSOLE_KIT_ALLOWLIST`; a PR that moves
one to the shared component removes it from the list, and nothing is added.
`web/scripts/check-page-anatomy.sh` checks the added lines of both apps for the
page-level rules (a page's own Save button, a hand-made "no permission"
message, a raw table in a page, a new SegmentedLens).

## List states in the shared table

`DataTable` and `ListCount` carry the states every list shares, so a page only says which one it is in:

- `showToolbar={false}`: no toolbar row (a first run or a refused read has nothing to search or arrange).
- An empty list disables the header's select-all checkbox and offers no sorting.
- `staleAt` (when the rows were read), `refreshFailed`, `onRefresh`: once the read is older than 5 minutes, or
  at once after a failed refresh, the footer says "Updated 12 minutes ago" with a refresh button
  (`data-slot="table-stale"`). The note keeps its own clock; the table does not re-render as time passes.
- `countUnavailable`: the pager shows the rows on screen without a total and "Page N"; Last page is disabled
  with its reason (`data-slot="table-last-page"`), as it is for a capped total (`rowCountCapped`). With
  `onRetryCount` the footer also says "Could not count" with Retry; a list with a title row leaves it out and
  uses `<ListCount failed onRetry>` (`data-state="failed"`, `data-slot="list-count-retry"`).
