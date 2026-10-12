# Activity panel

How an entity's activity and comments are shown, everywhere in the console. The
code is in `src/features/activity/`; the finding wiring is in
`src/features/findings/components/finding-activity.tsx` and
`src/features/findings/hooks/use-finding-activity-feed.ts`.

## The problem

Activity used to be a tab (the finding page) or a section (drawers) that
rendered the whole timeline inline, with the comment box under it. Once people
discuss a finding, the page becomes a long scroll of status changes and
comments, and the rest of the page is pushed out of reach.

## The decision

Activity is **a compact summary in the page that opens a panel**, not a tab
and not an inline feed.

- **`ActivityTrigger`** (in the page): "Activity · 3 comments", the latest
  comment as one line of plain text (or the latest change), its time, and a dot
  plus "N new" when something arrived since your last visit. One click, or `C`
  on a page, opens the panel; `C` focuses the comment box.
- **`ActivityPanel`** (a sheet on the shared `DetailSheet` frame): the full
  feed, the filter, the composer pinned at the bottom, and the live indicator.
  A right-hand drawer from `md`, a full-height bottom sheet on phones (390 px
  works: full width, the composer stays reachable).
- **`EntityActivity`** puts the two together and is what pages render.

The tab was removed rather than kept as a trigger: a tab that opens a sheet
instead of showing a panel breaks the tab pattern (`role="tab"` promises a
tabpanel), and the summary is more useful where people already look. On the
finding page it sits under the properties rail (sticky on `lg`), so it is
visible from every tab.

### URL and keyboard

| What                   | How                                                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Link to the open panel | `?activity=open` (pages). Drawers keep the state in memory so closing the drawer leaves no parameter.                      |
| Old links              | `?tab=activity` opens the panel and drops `tab` (finding and repository pages).                                            |
| Open                   | Click the summary; `C` (outside text fields) opens it on the comment box; in the findings drawer `⌘/Ctrl+C` does the same. |
| Close                  | `Esc`, the close button, or a click outside. Focus returns to the summary.                                                 |
| Send                   | `⌘/Ctrl+Enter` in the comment box.                                                                                         |
| Filter                 | All · Comments · Changes, a radio group (arrow keys move between them).                                                    |

## Patterns the panel follows

- **Comments are the feed;** a property change is one muted line
  ("Jamie changed status from Todo to In Progress · 2h"), and long runs of
  system events fold into "N hidden items · Load more".
- **A filter over the activity** (All · Comments · Changes); what people read
  most is the comments.
- **The composer sits at the bottom of the feed;** edited comments say
  "edited".
- **Reactions:** an emoji + count pill, highlighted when you reacted, showing
  who reacted on hover; a quick-reaction bar on hover and a searchable picker
  with "frequently used" and skin tones.

## Layout of the panel

```
Activity 27  · Live                                    [×]
cross-spawn ReDoS · 3 comments
[ All | Comments | Changes ]
─────────────────────────────────────────────────────────
                   [Load older]
──────────────── May 10 ────────────────
◎ Trivy recorded this finding · 3 days ago
⧉ 4 changes by System and 1 other · 3 days ago    Show ▾
┌ (JM) Jamie · 2 days ago · edited          [👍👀✅🎉☺⋯] ┐
│ Looks exploitable from the edge.                       │
│ (👀 2) (👍 1) (+)                                       │
└────────────────────────────────────────────────────────┘
──────── New since your last visit ────────
──────────────── Today ─────────────────
┌ (AN) An · 10 minutes ago · 🔒 Internal                  ┐
│ Patch in 7.0.5; rolling out tonight.                   │
└────────────────────────────────────────────────────────┘
                                   ( 2 new ↓ )
─────────────────────────────────────────────────────────
[Write | Preview]                   Markdown supported
┌──────────────────────────────────────────────────────┐
│ Add a comment…                                       │
└──────────────────────────────────────────────────────┘
[🔒 Internal]                  ⌘/Ctrl+Enter   [Send ▸]
```

### Signal and noise

- A person's comment is a **card**: avatar, name, time, "edited", the
  Internal badge, the body, attachments, reactions.
- Everything else (status, severity and assignee changes, scan detections, SLA
  warnings, AI triage, ticket links) is **one line** with a small icon, worded
  without jargon: "Status Confirmed → In progress", "Trivy recorded this
  finding".
- **A run of three or more consecutive events folds** into one row ("12
  changes by System and 2 others · Show"). Runs fold only in the All view, never across a day or the unread divider.

### Order and anchoring

- Oldest at the top, the composer at the bottom (chat and issue style).
- On open the panel scrolls to the first item you have not seen, under a
  **"New since your last visit"** divider; when everything was seen, to the
  bottom. Your own items are never "new" to you.
- Day separators ("Today", "Yesterday", "May 10"); relative times with the
  absolute time on hover.
- The last visit is kept per user and entity in browser storage (Phase A); see
  Phase B for the server-side marker.

### Filter

All · Comments · Changes. The panel opens on **Comments when there are any**,
otherwise All. Sending a comment while on Changes switches to All so you see it.

### Live updates

New items never move what you are reading. At the bottom, the feed follows
them; scrolled up, a floating **"N new ↓"** pill appears instead. A polite live
region announces "N new activity items" to screen readers.

### Composer

- Markdown, with a **Write / Preview** toggle; the preview is the same
  sanitised renderer as the feed.
- **Internal** (tenant-only, never sent to Jira or any integration) is a toggle
  in the composer and an amber badge on the comment.
- **The draft is saved** per user and entity as you type, so closing the panel
  loses nothing.
- **Optimistic send**: the comment appears at once ("Sending…"); a failure
  marks it "Not sent" with Retry and Discard.
- No attach button: comment attachments have no API yet (the old paperclip did
  nothing). See Phase B.

### Reactions

- Each comment has a hover / focus **action bar** at its top-right: 👍 👀 ✅ 🎉,
  "Add reaction" (the picker), and `⋯` (Add reaction, Copy text, Edit and
  Delete for your own comments). On touch screens only `⋯` shows, always
  visible.
- **Pills** under the body: emoji and count (`tabular-nums`, so the layout does
  not shift), highlighted when you reacted, a click toggles yours, a trailing
  `+` adds one. Hover names who reacted ("You, Jamie and 3 others reacted with
  👀"); more than three names list in the tooltip.
- Pills keep their **order of first use**, so counts going up never reshuffle
  them.
- Toggling is **optimistic** and rolls back on error; an added pill "pops"
  (150 ms scale, off under `prefers-reduced-motion`).
- Each pill is a toggle button: `aria-pressed`, and a name such as "👀 3
  reactions, including you, toggle".
- **The picker** is frimousse (headless, virtualised, keyboard navigable, about
  12 kB gzipped), loaded only when a picker opens. It has search, categories,
  skin tones and a "Frequently used" row per user. Its emoji data is served by
  the console (`/emojibase/en/*.json`, built from the pinned `emojibase-data`
  package), never from a CDN: the production CSP allows `connect-src 'self'`,
  and a CDN would learn who opens a picker.
- No notification per reaction (see Phase B for an opt-in digest).

### Performance

- Pages of activity load with **"Load older"** at the top; the reading position
  is kept when older items arrive above.
- Over 200 rows, off-screen rows skip layout and paint (`content-visibility:
auto` with an intrinsic size). No virtualisation library: rows have very
  different heights, and the browser does this without one.

## Security

- Comment and activity text is user- or scanner-supplied. Comment bodies render
  only through `MarkdownPreview` (the in-tree sanitiser: dangerous tags
  neutralised, attribute allowlist, unsafe URL schemes rewritten to `#`).
  Event lines are plain text. Nothing is rendered as raw HTML.
- The trigger's snippet is plain text built by `markdownSnippet` (no markup, no
  link targets).
- Attachment links go through the shared `SafeExternalLink` (`safeHref`,
  RFC-040 P0-B); a refused URL renders as plain text.
- Reactions: the API validates the emoji (one emoji sequence, normalised, no
  text, HTML or zero-width tricks), takes the tenant from the token, checks the
  parent finding's data scope and pentest membership, caps distinct emoji per
  comment and reactions per user, and rate-limits the endpoints.
- Internal comments never leave the tenant: no integration receives user
  comments (Jira sync posts only its own status text).
- Browser storage holds only the last-visit time, the draft and the frequently
  used emoji, per user. All of it is a convenience: every read and write is
  guarded and the panel works without it.

## Where it is used

| Surface                           | Feed                                                                                               | Comments |
| --------------------------------- | -------------------------------------------------------------------------------------------------- | -------- |
| Finding page (`/findings/[id]`)   | activities + comments + live channel                                                               | yes      |
| Findings list drawer              | same (shared hook)                                                                                 | yes      |
| Pentest finding sheet             | same; observers see no discussion, a locked campaign is read only                                  | yes      |
| Exposure drawer                   | state history                                                                                      | no       |
| Asset drawer ("Identity history") | merge, rename and normalise log                                                                    | no       |
| Repository page                   | derived from the repository's findings                                                             | no       |
| Sensor drawer                     | the sensor's operational log, in the same panel with its own chips and cursor pages (`customBody`) | no       |

Remediation tasks and campaigns, cycles, scans, components and threat models
have no activity or comment feed (no API); the "Timeline" sections elsewhere
only show created / updated dates and are not feeds. When one of them gets a
feed, it renders `EntityActivity`.

## Phase B: the follow-ups

What the API supports today, and what each next step needs.

| Item                         | API today                                                                         | Next step                                                                                                                                                                                                                                                                                  |
| ---------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Edit and delete own comments | `PUT` / `DELETE /findings/{id}/comments/{cid}`, author only; `edited` flag        | **Done** in the panel (`⋯` → Edit / Delete, "edited" marker). Missing: edits and deletes are not in the audit log and there is no edit history; record `comment.updated` / `comment.deleted` audit entries with the previous text hash, and keep revisions in `finding_comment_revisions`. |
| Reactions                    | `comment_reactions` (api PR "comment reactions and internal comments")            | **Done.** Follow-up: a per-user, opt-in daily digest ("N people reacted to your comment"), never one notification per reaction.                                                                                                                                                            |
| Reply threads + resolve      | none (`finding_comments` has no `parent_id`)                                      | Add `parent_id` (one level only) and `resolved_at` / `resolved_by` on the root. The panel renders replies indented under their root with "Reply" in the action bar and "Resolve thread" on the root; a resolved thread folds to one line ("Resolved by Jamie").                            |
| @mentions                    | none                                                                              | The composer suggests tenant members only (`GET /users?q=` scoped to the tenant). The API stores `mentions[]`, checks each user is in the tenant and can read the finding (data scope), and notifies them; text stays text (`@Name` rendered from the stored id, never from markup).       |
| Comment attachments          | `/attachments` exists for pentest only (`pentest_findings:*`, no comment context) | Add a `comment` context with `findings:write`, the existing 10 MB and type allowlist, `nosniff`, and `attachment` disposition for non-images; the composer gets a paperclip and drag-and-drop.                                                                                             |
| Server-side read marker      | none                                                                              | `PUT /findings/{id}/activity/read` storing `last_read_at` per user; replaces browser storage so the unread dot follows the user across devices.                                                                                                                                            |
| Cursor pagination            | page-based (`page`, `page_size`, newest first)                                    | A `before` cursor on `/activities` so a live insert cannot shift pages.                                                                                                                                                                                                                    |
| Thread summary (D9)          | none                                                                              | Opt-in only, and only with a local or tenant-approved model: a "Summarise" action on long threads; never automatic.                                                                                                                                                                        |
