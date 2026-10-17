# Register the OpenCTEM GitHub App

The GitHub App lets OpenCTEM post the **OpenCTEM gate** check and pull request
comments for CI runs (RFC-077). One app serves one deployment; each
organization installs it on its own GitHub organization from the console
(**CI/CD > Trust and gate > Pull request feedback**).

The app asks for the least it needs:

| Permission | Access | Why |
|---|---|---|
| Checks | Read and write | post the gate's check run on the commit |
| Pull requests | Read and write | the summary comment and inline review comments; find the pull request of a commit |
| Metadata | Read | required by GitHub for every app |
| Members (organization) | Read (required) | check, when an installation is bound, that the person binding it owns the GitHub organization; without it no organization installation can be bound |
| Contents | Read (optional) | read a merge commit's parents, so the check still lands on a pull request whose base moved before it was posted; a token with this permission is minted only for that read, for one repository. Without it such a check is skipped (the next run posts it) |

It reads no secrets and no workflows, and no code unless Contents is granted. Installation tokens live at
most one hour and cover only the repositories the installer selected.

## 1. Create the app from the manifest

Replace `CONSOLE` with the console's URL (for example
`https://app.openctem.io`) and `API` with the API's public URL (often the
same host). Save this as `github-app.html`, open it in a browser signed in
as an owner of the GitHub organization that will own the app, and press
**Create**:

```html
<form action="https://github.com/organizations/openctemio/settings/apps/new" method="post">
  <input type="hidden" name="manifest" id="manifest">
  <button type="submit">Create</button>
</form>
<script>
document.getElementById("manifest").value = JSON.stringify({
  "name": "OpenCTEM",
  "url": "https://openctem.io",
  "description": "Posts the OpenCTEM CI gate as a check and comments on pull requests.",
  "public": true,
  "hook_attributes": { "url": "API/api/v1/hooks/github-app", "active": true },
  "redirect_url": "CONSOLE/ci-cd",
  "callback_urls": ["CONSOLE/ci-cd/github-app/callback"],
  "setup_url": "CONSOLE/ci-cd/github-app/callback",
  "setup_on_update": true,
  "request_oauth_on_install": true,
  "default_permissions": { "checks": "write", "pull_requests": "write", "metadata": "read", "members": "read" },
  "default_events": ["repository"]
});
</script>
```

- `members: read` lets OpenCTEM check, during the install, that the person
  binding the installation is an owner of the GitHub organization. An app
  created without it binds no organization installation; add it under the
  app's **Permissions & events > Organization permissions > Members: Read**,
  and each organization accepts the new permission.
- `default_events: ["repository"]` sends repository renamed, transferred,
  archived and unarchived events. OpenCTEM then renames the repository's asset
  and CI pipelines (matched by GitHub's repository id, in the organization the
  installation is bound to) and archives or revives its pipelines, without
  waiting for the next CI run. A name pattern in a CI trust configuration is
  never edited by a webhook: update it yourself when a repository is renamed.
  An app created without the event: add **Repository** under **Permissions &
  events > Subscribe to events**.
- `public: true` lets other GitHub organizations install it (the hosted
  service). A deployment used by one GitHub organization can set `false`.
- For a GitHub Enterprise Server, post to
  `https://<GHES host>/organizations/<org>/settings/apps/new` instead.

GitHub creates the app and redirects to `CONSOLE/ci-cd?code=<code>`. Copy the
`code` from the address bar (it is valid for one hour) and convert it:

```sh
curl -sS -X POST -H "Accept: application/vnd.github+json" \
  https://api.github.com/app-manifests/<code>/conversions > github-app.json
```

`github-app.json` holds the app's id, slug, client id, client secret,
webhook secret and private key (`pem`). Treat the file as a secret and
delete it after step 2.

## 2. Configure the API

Store the private key as a file readable only by the API, and set:

| Variable | From `github-app.json` |
|---|---|
| `GITHUB_APP_ID` | `id` |
| `GITHUB_APP_SLUG` | `slug` |
| `GITHUB_APP_CLIENT_ID` | `client_id` |
| `GITHUB_APP_CLIENT_SECRET` | `client_secret` |
| `GITHUB_APP_WEBHOOK_SECRET` | `webhook_secret` |
| `GITHUB_APP_PRIVATE_KEY_FILE` | path of the file holding `pem` |

```sh
jq -r .pem github-app.json > /run/secrets/github-app.pem && chmod 0400 /run/secrets/github-app.pem
```

For GitHub Enterprise Server also set `GITHUB_APP_API_URL`
(`https://<host>/api/v3`) and `GITHUB_APP_WEB_URL` (`https://<host>`).
Restart the API. With any value missing the app stays off and the API logs
which variables to set.

## 3. Check

- `GET /api/v1/ci/scm-apps` answers `"github": {"configured": true, "slug": "<slug>"}`.
- On the app's page (GitHub > Settings > Developer settings > GitHub Apps >
  OpenCTEM > Advanced) the first webhook delivery after an install shows `204`.

## 4. Install for an organization

An owner or administrator of the OpenCTEM organization opens **CI/CD > Trust
and gate > Pull request feedback > Install on GitHub**, picks the GitHub
organization and repositories, and authorizes. OpenCTEM binds the
installation only when:

- the person's own GitHub authorization shows they own the installation's
  account: an owner (admin) of the GitHub organization, or the GitHub user
  account itself. A member who can merely see the installation cannot bind
  it;
- the install link was theirs, is used once and is at most 15 minutes old;
- they confirmed their identity again (second factor or password) within
  the last 10 minutes.

The GitHub user token obtained for the check is revoked right after it. An installation is bound to
one OpenCTEM organization. Removing it on GitHub, or suspending it, stops
OpenCTEM from using it at once (webhook).

Then make **OpenCTEM gate** a required status check in the repository's
branch protection or ruleset, and **set its expected source to the OpenCTEM
app** (ruleset: *Require status checks to pass* > the check > source
*OpenCTEM*; branch protection: the app next to the check name). Without a
pinned source, any token that may write checks could post a check with the
same name and satisfy the rule: a workflow's own token can, and a pull
request can add a workflow.

## What it posts

After each CI run's verdict on a GitHub repository whose organization bound
an installation:

- a check run **OpenCTEM gate** on the commit (success, failure, or neutral in
  warn mode) with the counts, the reasons and up to 50 line annotations. The
  check of a commit takes the strictest of the latest verdicts of every
  pipeline on that commit: GitHub keeps the latest check of a name, so a
  second workflow (or a later run of another pipeline) that passes cannot
  replace a failing check; a re-run of the same pipeline replaces its own
  earlier verdict. For a
  pull request it goes on the pull request's head as GitHub reports it, and
  only when the run judged the pull request's current merge commit: a run can
  never put its verdict on another commit;
- one summary comment on the pull request, updated in place by later runs of
  the same pipeline.

When a default-branch commit comes from a merged pull request whose last
gate verdict was not a pass, the notification `ci.ungated_merge` is sent
(Settings > Notifications): the merge did not wait for the gate.

Posting runs in the background (every 15 seconds); it never changes a
verdict. A failed post is retried up to eight times, 30 seconds apart and
doubling up to 30 minutes (about an hour in all), and a GitHub rate limit is
retried, never final. When GitHub recomputes a pull request's merge commit
because its base branch moved, a run that judged the same head still posts
its check on that head. The check is `action_required` when only a scanner
failure failed the gate (nothing in the code was judged); findings the policy
lists in comment mode are notice annotations and are marked as not blocking
in the comment.

## Rotate

- Private key: generate a new key on the app's page, replace the file,
  restart the API, delete the old key on GitHub.
- Webhook secret: set a new one on the app's page and in
  `GITHUB_APP_WEBHOOK_SECRET`, then restart.
- Client secret: generate a new one, update `GITHUB_APP_CLIENT_SECRET`,
  restart, delete the old one.
