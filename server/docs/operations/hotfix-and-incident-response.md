# Hotfix and incident response

How a vulnerability or another defect that has reached a production
installation is contained, fixed, released, deployed and disclosed. It is
written for the maintainers and for operators of installations we run; an
operator of a self-hosted installation can follow the containment, deploy and
rollback parts as they are.

The tools named here exist and are documented elsewhere; this page is the
order to use them in:

- release train and hotfix mode: [RFC-037](../rfcs/RFC-037-versioning-and-release-train.md)
  (section 4.3) and `.github/workflows/release-train.yml`;
- CI, the merge queue and the security gate: [ci-cd.md](../development/ci-cd.md);
- migrations: [migrations.md](../development/migrations.md) and
  [safe deploy and migrations](../deployment/safe-deploy-and-migrations.md);
- alerts and their runbooks: [monitoring.md](monitoring.md);
- suspending an organization or blocking an account: [suspension.md](suspension.md);
- the reporting channels and public commitments: [SECURITY.md](../../../SECURITY.md).

## 1. Severity

The incident lead proposes a severity during triage; the maintainer decides it
and may change it as facts arrive. When in doubt, take the higher level and
lower it later.

| Level | Meaning | Examples |
|---|---|---|
| **S1 critical** | Data of one organization reachable by another, authentication or authorization bypass, remote code execution, active exploitation of any vulnerability, production down or losing data | a route that returns another tenant's findings; a crafted sensor report that crashes every API replica in a loop; a leaked signing key |
| **S2 high** | Serious vulnerability without known exploitation, or a core flow broken for many organizations with no workaround | privilege escalation inside one organization; scans stall for every organization; sensors cannot submit results |
| **S3 medium** | Limited vulnerability (needs high privilege or unlikely conditions), or a defect with a workaround | an information leak to an organization's own administrator; one integration fails; a misleading error that hides the real cause |
| **S4 low** | Hardening, cosmetic or rare defect | a missing security header on a static page; a wrong label |

Target times, from the moment the report or alert reaches a maintainer:

| Level | Acknowledge | Contain (mitigation in place) | Fix released | Disclose |
|---|---|---|---|---|
| S1 | 1 hour | 4 hours | 7 days for a vulnerability (24 hours when production is down) | advisory with the fixed release |
| S2 | 1 business day | 1 business day | 30 days | advisory with the fixed release |
| S3 | 3 business days | when a cheap one exists | 90 days, usually with the next train | advisory or release note with the fix |
| S4 | 3 business days | not required | best effort, next train | release note |

The public commitments in [SECURITY.md](../../../SECURITY.md) (acknowledgement
within 3 business days, triage within 10, fix targets by CVSS) are the outer
bound for a reported vulnerability; the targets above are tighter on purpose.
For a vulnerability, the CVSS 3.1 score maps as critical = S1, high = S2,
medium = S3, low = S4, and active exploitation raises any level to S1.

**Who decides.** The maintainer decides the severity, the containment that
changes production, every production deploy, every write to a production
database, and the disclosure date. The incident lead (whoever picked the
incident up) runs the checklist, keeps the timeline and proposes each step.

## 2. Intake

An incident starts from one of three places. Open one private incident record
(the maintainers' tracker, never a public issue) and keep its timeline in UTC
from the first minute.

- **A private vulnerability report:** an e-mail to the security address or a
  GitHub private vulnerability report (a draft security advisory visible only
  to the reporter and the maintainers). Acknowledge it in the same channel.
- **A monitoring alert:** an alert from the monitoring stack
  ([monitoring.md](monitoring.md)), for example `ContainerRestarting`,
  `ApiPanics`, `ScanRunsStuck`, `IngestJobsDead` or `HostClockOffsetLarge`.
- **A user or customer report:** through support or a public issue. If a
  public issue turns out to describe an unfixed vulnerability, ask the
  reporter to continue privately, hide or lock the issue, and move the details
  into a draft advisory.

**Never discuss an unfixed vulnerability in public:** no public issue, pull
request, discussion, commit message, changelog fragment, chat channel with
outside members or status page text that describes how to exploit it, until
the advisory is published. Describe the change neutrally until then (for
example "validate the producer index in ingest", not "crash the API with a
crafted report").

## 3. Triage checklist

Answer each question in the incident record before choosing a path:

- [ ] **Reproduced?** A failing test, a request, or a log line with a stack
      trace. A report that cannot be reproduced stays open with the reporter.
- [ ] **Exploitable, and by whom?** Anonymous, any signed-in user, an
      organization administrator, a paired sensor, a platform operator. What
      the attacker needs first.
- [ ] **Affected versions.** Find the commit that introduced it and list the
      release tags that contain it:
      `git tag --contains <commit> 'v*'`. Check whether the previous release
      has it too (`git log vA..vB -- <path>`); that decides whether a
      rollback helps.
- [ ] **Affected editions and deployments.** Community, Enterprise (extension
      overlay), the hosted service; Docker Compose with the deployment kit,
      the all-in-one image, Helm, the release archives (systemd). A defect in
      the API image affects all of them; one in the kit, a chart or a
      gateway file affects only that deployment type.
- [ ] **Data and tenant isolation impact.** Which data, which organizations,
      read or write, and whether audit logs show it happening. A cross-tenant
      read or write is S1 by definition.
- [ ] **Already exploited?** Search the API and gateway logs and the audit log
      for the pattern over the whole retention window. Write down the query
      and the result, also when it is "nothing found".
- [ ] **Is the fix in this repository, a sensor, sdk-go, a connector, the kit
      or a chart?** (Section 6 for components with their own release line.)
- [ ] **Severity** (section 1) agreed with the maintainer.

## 4. Containment before the fix

Contain first, fix second. Use the fastest lever that stops the harm, and
record in the incident timeline who applied it, when, and how to undo it.
Every lever that changes production needs the maintainer's go.

### 4.1 Switches and settings (minutes)

- **Switch a module off.** For every organization: an installation-scope
  module comes from platform configuration and answers
  `403 MODULE_NOT_ENABLED` with `disabled_by_platform`. For one
  organization: a deny in the admin console (Organizations > Modules, with a
  reason and an authenticator code). Off means off on REST, MCP, jobs and
  automations ([modules.md](../architecture/modules.md)). Core modules cannot
  be switched off.
- **Environment switches** (reference:
  [environment variables](../configuration/environment-variables.md)), set
  through the deployment's configuration (the kit's `openctem_api_env`, the
  Helm values, the compose `.env`) and applied with a restart of the API:
  sign-up (`SIGNUP_MODE`), social sign-in (`OAUTH_*_ENABLED`), rate limits
  (`RATE_LIMIT_ENABLED`, `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`,
  `AI_RATE_LIMIT_*`), background features (`ASSET_COVERAGE_ENABLED`,
  `ASSET_ENRICHMENT_ENABLED`, `CERT_MONITOR_ENABLED`,
  `EASM_DNS_CHECKS_ENABLED`), ingest concurrency (`INGEST_WORKERS`,
  `INGEST_MAX_RUNNING_PER_TENANT`).
- **Gateway or edge rule.** Block or rate-limit the affected path at the
  gateway or the web application firewall in front of it. Match the narrowest
  path and method; record the rule so it is removed after the fix.
- **Pause schedules.** Pause the scan schedule or the automation that
  triggers the defect (its Pause action), rather than stopping a whole
  component.

### 4.2 Credentials (minutes)

- Revoke the API key, the sensor (delete or disable it on the Sensors page;
  a shared sensor in the admin console), or a user's sessions (admin console,
  Users > Revoke sessions).
- Block an account or suspend an organization when one of them is the source
  ([suspension.md](suspension.md)).
- A leaked secret is rotated, not only revoked: the encryption key has its
  own procedure ([encryption-key-rotation.md](../deployment/encryption-key-rotation.md)).
  Never paste a secret into the incident record or a chat; refer to it by name.

### 4.3 Quarantine a poison job

A job that crashes or wedges a worker is handed out again after every restart
(its lease expires, the queue claims it again). Ingest jobs stop being
claimed once `attempts` reaches `max_attempts`, but a job can also block a
scan's next steps on every attempt. When the job is identified and the fix is
not yet deployed, mark that one job dead:

1. Identify it from the log line just before the crash (job id and
   organization id) or from the jobs being processed:

   ```sql
   SELECT id, tenant_id, kind, attempts, max_attempts, locked_at
   FROM ingest_jobs WHERE status = 'processing' ORDER BY locked_at;
   ```

2. **Get the maintainer's explicit approval for the write, and record it**
   (who, when, which job id) in the incident record. A production database
   is read-only otherwise.
3. Mark exactly that job dead, scoped by organization and id, in a
   transaction that checks the row count before committing:

   ```sql
   BEGIN;
   UPDATE ingest_jobs
      SET status = 'dead', error = 'quarantined by operator: <incident id>',
          public_error = 'apply_failed', locked_by = NULL, locked_at = NULL,
          updated_at = NOW()
    WHERE tenant_id = '<org id>' AND id = '<job id>'
      AND status IN ('pending', 'processing');
   -- exactly 1 row, else ROLLBACK
   COMMIT;
   ```

   `apply_failed` keeps the stored report, so the organization can retry the
   upload once the fix is deployed. Never delete the row or its payload.
4. Watch the restart count stop climbing and the queue drain. Other stuck
   work (a scan run whose next step never dispatched) is handled after the
   fix, through the console, not by more database writes.

Durable jobs follow the same rule with `durable_jobs` ([durable-jobs.md](../architecture/durable-jobs.md)).

### 4.4 Roll back or scale (minutes to an hour)

- **Roll back** to the previous release's image digests when the previous
  release does not have the defect (triage, "Affected versions"). With the
  deployment kit:
  `ansible-playbook -i $INV playbooks/71-rollback.yml -K -e apply_rollback=true`.
  It starts the previous release without its migration job and verifies;
  migrations are not reversed (an older API runs on a newer schema in normal
  releases). If the older release misbehaves on the migrated database, restore
  the pre-upgrade backup with `openctem-restore` (kit README, "Upgrade and
  rollback"). On Helm, roll back to the previous revision; a Git-driven
  deployment points back to the previous digest.
- **Scale** API replicas or workers when the defect is load-related, and
  lower the per-organization concurrency instead of raising the total.

## 5. The fix

### 5.1 Where the fix is written

- **A vulnerability:** write the fix privately. Open (or use) the draft
  security advisory on the repository and create its **temporary private
  fork** from the advisory page. Push the fix branch there and review it
  there. CI does not run in a temporary private fork: run the build, vet,
  `make lint-new` and the touched packages' tests locally, including the new
  regression test, and record the results in the advisory.
- **Any other defect:** a normal branch and pull request against `develop`.

The fix always has a **regression test that fails without it**, and the
security rules of every change apply (threat model, authorization and
tenant-isolation impact, cross-tenant negative test).

### 5.2 Land it on develop first

Every fix lands on `develop` through the merge queue first, also for a
hotfix: the hotfix train cherry-picks `develop` commits, and the release pull
request's fast path proves each pick has the same patch-id as a `develop`
commit whose checks passed.

For a vulnerability fixed privately, open the public pull request from the
private branch only when the release can follow right behind it (the same
day): neutral title and description, no exploit detail, the changelog
fragment as neutral as the title. The window between the public pull request
and the published release is the exposure window; contain first (section 4)
so that window does not matter.

- **Security gate.** A fix that touches security-sensitive paths is labelled
  `security-sensitive`. The fast path is the maintainer's acknowledgement:
  the `security-ack` label, or a `/security-ack` comment from the GitHub
  mobile app or an e-mail reply ([ci-cd.md, security gate](../development/ci-cd.md#security-gate)).
  Only the maintainer acknowledges; nobody else adds the label.
- **Required checks are never skipped, and nothing is admin-merged.** The
  merge queue runs the full tier on every pull request, including a hotfix.
  The administrator bypass described in ci-cd.md exists for a gate that is
  itself broken and is the maintainer's decision with a written follow-up; a
  hotfix never uses it to save time. If CI is slow, contain harder; do not
  bypass.

### 5.3 Train or hotfix

- **Train** (`mode: train`): when `develop` is green and releasable soon, a
  normal release carries the fix with everything else. Prefer it when the
  difference is an hour or two and nothing on `develop` is risky.
- **Hotfix** (`mode: hotfix`): the last tag plus only the picked fixes. The
  version is the last tag's patch + 1 (`v0.18.1` -> `v0.18.2`); the workflow
  refuses another one. It requires that `main` has not changed since the last
  tag.

Run it from the Actions page (Release Train > Run, with "Use workflow from"
set to develop: a run from any other branch stops at once) or the command
line with `--ref develop`, dry run first:

```bash
# merge commits of the fix pull requests on develop, oldest first
gh workflow run release-train.yml -R openctemio/openctem --ref develop \
  -f mode=hotfix -f cherry_picks="<sha1> <sha2>" -f dry_run=true
# read the run summary: version, notes, the cherry-picks applied cleanly
gh workflow run release-train.yml -R openctemio/openctem --ref develop \
  -f mode=hotfix -f cherry_picks="<sha1> <sha2>" -f dry_run=false
```

The workflow builds `release/vX.Y.Z` from the last tag, cherry-picks each
commit with `-x` (`-m 1` for a merge commit), adds the version commit
(`api/deploy/VERSION`), opens the release pull request into `main` and queues
it.

**When a cherry-pick conflicts** the run stops with "backport it by hand":

1. Branch from the last tag: `git switch -c backport/vX.Y.Z-<slug> vA.B.C`.
2. `git cherry-pick -x <sha>` and resolve the conflict with the smallest
   change that keeps the fix and its regression test. Do not pull in
   unrelated `develop` changes to make it apply.
3. Run the touched packages' tests on that branch.
4. Push the branch to this repository and pass the backport commit's sha in
   `cherry_picks`. It now applies cleanly.
5. The release pull request then runs its full tier (the fast path verifies
   only picks with a matching `develop` patch-id). After the tag, the
   post-release pull request merges `main` back into `develop` and brings in
   anything the backport adapted.

### 5.4 Migrations in a hotfix

Avoid them. When the fix needs one, it must be:

- **additive and reversible:** a new nullable column, a new index built
  concurrently, a new table; a working down migration. Never a drop, a
  rename, a type change or a data rewrite in a hotfix;
- **expand-contract safe** (`scripts/check-migrations.sh`), so the previous
  release still runs on the new schema and the kit's rollback stays valid;
- **rehearsed** on a restored copy of a production-sized database before the
  release deploys (the deploy rehearsal of the installation, or a restore
  drill database).

A merged migration never changes; fix a bad one with a new one. Name the
migration and any operator step in the changelog fragment.

## 6. Release

When the release pull request merges, **Release Publish** tags `vX.Y.Z` on
the merge commit, **Docker Publish** builds and pushes every image, signs each
digest with keyless cosign (identity
`https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/vX.Y.Z`,
issuer `https://token.actions.githubusercontent.com`), attaches an SPDX SBOM
attestation and a signed build provenance, and publishes the GitHub Release.
Signing runs after the last image is built: wait for it before deploying.

Then:

- [ ] **Verify the signature** of the images you will deploy:

  ```bash
  cosign verify ghcr.io/openctemio/openctem-api:vX.Y.Z \
    --certificate-identity "https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/vX.Y.Z" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  gh attestation verify oci://ghcr.io/openctemio/openctem-api:vX.Y.Z --owner openctemio
  ```

- [ ] **Release notes.** Edit the GitHub Release: a `Security` section first,
      with the advisory link (after it is published), the affected and fixed
      versions, and the upgrade instruction.
- [ ] **Follow-up pull requests** that Release Publish opens: `main` merged
      back into `develop` (merge with the queue, merge commit, never squash),
      and the helm-charts `appVersion` bump. If the back-merge conflicts,
      Release Publish opens an issue instead; resolve it by hand on
      `chore/post-release-vX.Y.Z`.
- [ ] **`api/migrations/released.json`:** run `make -C api
      migrations-released`. It changes the file only for a release line that
      still shipped the earlier migration tool (v0.15.x and older); when it
      changes, open a pull request at once, since CI checks it against the
      tags.
- [ ] **Changelog.** The fix's fragment (`api/changelog.d/<slug>.md`,
      category `Security` or `Fixed`) came with the fix. `changelog.py
      release` folds every fragment on `develop`, so it is not run for a
      hotfix; the picked fragments are folded with the next train, whose
      section notes that the fix shipped in `vX.Y.Z`.

## 7. Deploy

Deploy to the staging or test installation first when the incident allows it
(S1 with production down may go straight to production after the signature
check and the preflight), then production. **A production deploy needs the
maintainer's explicit go**, given after seeing the version, the migrations
and the rollback plan.

With the deployment kit (`openctemio/openctem-ansible`):

1. `scripts/vendor-release.sh vX.Y.Z`: vendors the release's gateway files and
   least-privilege SQL and prints the image digests for `versions.yml`. Keep
   the previous release in `versions.yml`: rollback deploys it. Open the kit
   pull request.
2. Verify each printed digest with cosign (section 6). The play verifies them
   again before it pulls anything.
3. `ansible-playbook -i $INV playbooks/00-preflight.yml` (read-only: OS,
   Docker, firewall, **clock synchronised**, sshd).
4. `ansible-playbook -i $INV playbooks/50-openctem.yml -K --check --diff -e apply_openctem=true -e openctem_version=vX.Y.Z`.
   The diff must show only the new digests, release paths and expected
   configuration. Anything else stops the deploy.
5. Report to the maintainer: version, migrations (none for an image-only
   hotfix), the diff summary, the rollback command. Wait for the go.
6. On the go: merge the kit pull request, run step 4 without `--check`, then
   set `openctem_version` in the inventory. The play backs up first, keeps the
   running compose file as `compose.prev.yml`, migrates before the API starts,
   verifies, and rolls back by itself on failure.

**Verification checklist** (record each result):

- [ ] `sudo openctem-verify` passes;
- [ ] the web console loads, sign-in works, the admin console redirects to
      its sign-in;
- [ ] no new ERROR lines in the API log since the start
      (`docker logs --since 15m <api container> 2>&1 | grep level=ERROR`);
- [ ] container restart counts stay flat for 15 minutes;
- [ ] the defect itself is gone on production: the failing request now
      succeeds, the stalled work moves (scan runs finish, the ingest queue
      drains), the alert resolves;
- [ ] sensors heartbeat and claim work.

**Roll back when** verification fails, the API restarts more than twice in 15
minutes, the error rate is higher than before the deploy, or the fix does not
fix the defect and the release is otherwise worse:
`ansible-playbook -i $INV playbooks/71-rollback.yml -K -e apply_rollback=true`
(section 4.4 for what it does and does not undo).

## 8. Sensors, sdk-go and connectors

The scanning sensor, sdk-go and the connectors have their own repositories
and release lines (RFC-037 section 6): **Release Prepare** opens the release
pull request into their `main` (it folds their `changelog.d`), and **Release
Tag** tags its merge, which runs the binary release and the signed image
publish. When the fix is there:

1. Fix it in that repository (privately first for a vulnerability, as in
   section 5.1) and cut a patch release with Release Prepare (set the
   version input to the next patch when the proposal is a minor). A fix in sdk-go needs an
   sdk-go release first, then a sensor (or connector) release that depends on
   it.
2. Running platforms learn the new release from the signed release feed
   (rebuilt every 6 hours and after each platform release): the Sensors page
   shows "update available" and the install snippets pin the new image. No
   platform release is needed for that.
3. **Raise the floor** when the old release must stop working with the
   platform: the product's `min` in `versions.yaml` (a sensor below it is
   degraded, `version_unsupported`), or add the SDK release to
   `sdk.advisories` (a sensor built with it is degraded with the warning
   `sdk_advisory`). Run `.github/scripts/release/sync-versions.sh`; this is a
   platform change and ships with a platform release (hotfix or train).
   Where the risk is acute, revoke or disable the affected sensors instead of
   waiting for the floor.
4. **Tell operators** in the advisory and the release notes of both
   components: which sensor or connector versions are affected, the fixed
   version, and the upgrade command for each install type.
5. **Coordinated upgrade.** When the fix changes the contract between the
   platform and its producers, platform and producers upgrade together, in
   the order the upgrade note gives, as for CTIS 2.0
   ([ctis-2-upgrade.md](ctis-2-upgrade.md)): publish the producers first
   when the new platform refuses old producers, list the minimum producer
   versions in the note, and keep queued work that the old format cannot
   apply visible rather than dropped.

## 9. Disclosure

- **Security advisory.** Publish the GitHub security advisory on the
  repository with the fixed release: affected versions (`< vX.Y.Z` within the
  supported line), patched version, severity with the CVSS 3.1 vector, a
  description at the level an operator needs to judge exposure, workarounds
  (the containment from section 4 that an operator can apply), credits.
- **CVE.** Request a CVE identifier from the advisory page for a confirmed
  vulnerability in released software, before publishing, so the advisory
  carries it.
- **Credit** the reporter as they asked (advisory, release notes, the
  security acknowledgements page), or not at all if they prefer.
- **Timeline.** Agree the disclosure date with the reporter. The default is
  the day the fixed release is published; at the latest 90 days after the
  report even without a fix, with the reporter told in advance.
- **Customers.** For the hosted service and for Enterprise customers,
  notify the affected customers directly, in their language, within the
  contractual window, before or with the public advisory; for an incident
  that touched their data, say what was affected and what they need to do.
  Update the status page during and after a production incident.

## 10. After the incident

Within five business days of closing an S1 or S2 incident (S3 when it was
instructive), write a blameless post-incident review in the private incident
record:

```markdown
# Post-incident review: <title>

Severity: S? | Duration: <first impact> to <resolved> (UTC) | Lead: <role>

## Summary
Two or three sentences: what broke, for whom, how long.

## Impact
Organizations, users, data affected; what they saw.

## Timeline (UTC)
- hh:mm first impact
- hh:mm detected (how: alert, report)
- hh:mm acknowledged
- hh:mm contained (what)
- hh:mm fix merged on develop / released / deployed
- hh:mm verified

## Root cause
The defect and the conditions that triggered it.

## Why tests and monitoring missed it
Which test was absent; which alert fired late or not at all.

## What went well / what was hard

## Action items
| Action | Owner | Due | Tracking |
|---|---|---|---|
| Regression test (merged with the fix) | | | |
| Alert or runbook for this failure class | | | |
| ... | | | |
```

Mandatory outcomes:

- **A regression test** that fails without the fix (it ships with the fix).
- **The failure class is monitored:** an alert in the monitoring stack with a
  runbook entry in [monitoring.md](monitoring.md), or a note there of why the
  existing alert covers it.
- The class is searched for elsewhere in the code (a sweep), with the result
  recorded in the review.

## 11. Roles and authority

- **Production deploy:** only on the maintainer's explicit go, after the
  version, the migrations and the rollback have been reported.
- **Production database writes:** read-only by default. A write needs the
  maintainer's approval for that exact statement, recorded in the incident
  record with the time and the row count, run in a transaction scoped by
  organization and id.
- **Break-glass.** When the maintainer cannot be reached during an S1 and
  harm is ongoing, the operator on duty may apply a containment lever from
  section 4 that is reversible and does not touch data (a module or feature
  switch, a gateway rule, revoking a credential, a rollback with the kit).
  Nothing else: no database writes, no deploy of a new release, no merge. The
  action is recorded as it happens and reported to the maintainer at once.
- **No secrets in logs, chat or the incident record.** Refer to keys and
  tokens by name; redact tokens, cookies and personal data from pasted logs;
  reports quote aggregates, not organization data. Organization names stay
  out of public text.

## Appendix A. Command checklist

```bash
# --- triage
git tag --contains <bad-commit> 'v*'
git log --oneline vA.B.C..vA.B.D -- <path>          # did the last release add it?

# --- contain (kit host): roll back to the previous release
ansible-playbook -i $INV playbooks/71-rollback.yml -K -e apply_rollback=true

# --- hotfix release (fix already merged on develop)
gh workflow run release-train.yml -R openctemio/openctem --ref develop \
  -f mode=hotfix -f cherry_picks="<merge-sha>" -f dry_run=true
gh run list -R openctemio/openctem -w release-train.yml -L 1
gh workflow run release-train.yml -R openctemio/openctem --ref develop \
  -f mode=hotfix -f cherry_picks="<merge-sha>" -f dry_run=false
gh pr list -R openctemio/openctem --base main --head release/vX.Y.Z
gh run list -R openctemio/openctem -w docker-publish.yml -L 1  # wait for signing

# --- verify the images
cosign verify ghcr.io/openctemio/openctem-api:vX.Y.Z \
  --certificate-identity "https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
make -C api migrations-released                     # changes only for v0.15.x and older

# --- deploy (kit clone)
scripts/vendor-release.sh vX.Y.Z
ansible-playbook -i $INV playbooks/00-preflight.yml
ansible-playbook -i $INV playbooks/50-openctem.yml -K --check --diff \
  -e apply_openctem=true -e openctem_version=vX.Y.Z
# maintainer's go, then the same without --check
sudo openctem-verify
```

## Appendix B. Worked example: three production problems in one morning

A real sequence on a production installation running `v0.18.1`, with
organization names and identifiers left out.

**1. Clock jump (S2).** The production host's clock jumped about 6.9 hours
forward; chrony stepped it back at 06:25 UTC. Afterwards, one externally
hosted sensor kept signing its requests about 6.9 hours ahead, and the
platform refused its results (sensor request signatures allow 2 minutes of
skew). Sensors on the platform's own hosts recovered by themselves.

- Containment: none needed on the platform once its clock was right. The
  sensor's own host clock was checked (`chronyc tracking`) and corrected, and
  that sensor was restarted to leave its back-off and redo the work it had
  claimed with the wrong time.
- Lesson: the preflight checks the clock before every deploy, and
  `HostClockUnsynchronised` / `HostClockOffsetLarge` cover the platform host;
  a sensor's host clock is the sensor operator's to monitor. The sensor error
  names the offset and which side is wrong.

**2. A misleading "Scan not found" (S3).** Run now on a paused workflow scan
answered `404 Scan not found`. The scan existed; it referenced a system
template stored with another organization's id, so the tenant-scoped lookup
correctly refused it, and the error named the wrong object. The refusal was
right (no data crossed organizations); the message and the stored data were
wrong. It went through a normal pull request and the next train.

**3. API crash loop from a poison ingest job (S1).** The API restarted 134
times. Each restart died in the ingest worker:

```
panic: runtime error: index out of range [3] with length 3
ingest.(*Service).IngestV2Segment  ingest/v2.go:149
```

Ingest appends a derived web-origin asset per endpoint after the producer's
assets, and a loop indexed the producer list with the full list's positions.
The worker goroutine had no recover, so the process died, and the queue
handed the same job out again after each restart. Scan runs stalled
mid-workflow (steps pending, no sensor claiming).

- Detection: container restart count and a stalled run, then the panic stack
  in the API log (`ContainerRestarting`, `ScanRunsStuck`).
- Triage: no ingest code changed between `v0.17.0` and `v0.18.1`, so a
  rollback would not help. A crafted report could trigger the same panic from
  any paired sensor, so it was treated as a denial-of-service vulnerability as
  well as an outage.
- Containment offered: mark the one poison job dead (section 4.3), which
  needs the maintainer's approval for the production write.
- Fix (openctem pull request 3625): derived assets beyond the producer list
  are skipped in producer counts, and a panic while processing one job is
  logged with its stack and makes that job dead (`apply_failed`) instead of
  crashing the process. Regression tests:
  `TestAssetOutcomes_DerivedAssetsPastProducerList`,
  `TestIngestWorker_PanicIsDeadNotACrash`.
- Release: `develop` was green and a train (`v0.19.0`) could be cut within
  the hour together with a required sensor version floor, so the train was
  chosen. The hotfix alternative would have been:

  ```bash
  gh workflow run release-train.yml -R openctemio/openctem --ref develop \
    -f mode=hotfix -f cherry_picks="<merge commit of the fix>" -f dry_run=false
  # -> v0.18.2 = v0.18.1 + the fix + the version commit
  ```

- Follow-ups: with the fix, the failure class (one job takes down the
  process) becomes a dead job and an `IngestJobsDead` alert rather than a
  crash. Action item from the review: sweep the other background worker
  loops for the same missing recover.
