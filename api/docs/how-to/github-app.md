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

It reads no code, no secrets and no workflows. Installation tokens live at
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
  "default_permissions": { "checks": "write", "pull_requests": "write", "metadata": "read" },
  "default_events": []
});
</script>
```

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
installation only when the person's own GitHub authorization reaches it and
the install link was theirs (valid 15 minutes). An installation is bound to
one OpenCTEM organization. Removing it on GitHub, or suspending it, stops
OpenCTEM from using it at once (webhook).

Then make **OpenCTEM gate** a required status check in the repository's
branch protection or ruleset.

## What it posts

After each CI run's verdict on a GitHub repository whose organization bound
an installation:

- a check run **OpenCTEM gate** on the commit (success, failure, or neutral in
  warn mode) with the counts, the reasons and up to 50 line annotations. For a
  pull request it goes on the pull request's head as GitHub reports it, and
  only when the run judged the pull request's current merge commit: a run can
  never put its verdict on another commit;
- one summary comment on the pull request, updated in place by later runs of
  the same pipeline.

Posting runs in the background (every 15 seconds, retried up to five times);
it never changes a verdict.

## Rotate

- Private key: generate a new key on the app's page, replace the file,
  restart the API, delete the old key on GitHub.
- Webhook secret: set a new one on the app's page and in
  `GITHUB_APP_WEBHOOK_SECRET`, then restart.
- Client secret: generate a new one, update `GITHUB_APP_CLIENT_SECRET`,
  restart, delete the old one.
