# Post the CI gate to GitLab merge requests

OpenCTEM can set the **OpenCTEM gate** commit status on each CI run's commit
and keep one note on the merge request (RFC-077). It uses a GitLab **group
access token** you create; no OpenCTEM-side app is needed.

## 1. Create the token in GitLab

In the top-level group (or the subgroup that holds the projects):
**Settings > Access tokens > Add new token**

| Field | Value |
|---|---|
| Name | `OpenCTEM` |
| Role | **Developer** (enough to set commit statuses and write notes) |
| Scopes | **api** (GitLab has no narrower scope that can set a commit status) |
| Expiration | your policy; OpenCTEM shows the date |

The token belongs to a bot user that is a member of that group only, so it
reaches only that group's projects.

## 2. Connect it in OpenCTEM

An owner or administrator: **CI/CD > Trust and gate > Pull request feedback >
Connect GitLab group**, enter the GitLab host (empty for gitlab.com), the
group path and the token, and confirm with the second factor.

OpenCTEM checks with GitLab that the token is active, has the `api` scope and
belongs to a direct member of the group, then stores it encrypted with the
application key. The token is never shown again or returned by the API;
**Disconnect** deletes it.

## 3. Make it required

The status is named **OpenCTEM gate**. With **Settings > Merge requests >
Pipelines must succeed** on, a failed external status blocks the merge.
GitLab Ultimate's **status checks** can also require it by name.

## What it posts

- a commit status `success` or `failed` on the run's commit. For a merge
  request run, only when the run judged the merge request as it stands:
  - a merge request pipeline on the head: the commit is the merge request's
    current head as GitLab reports it;
  - a merged results pipeline (`refs/merge-requests/<n>/merge`), whose commit
    is the merge of the head into the target: the pipeline is the merge
    request's head pipeline and its commit is the run's. The status is
    attached to that pipeline, which is the one the merge request shows.
  - Merge train pipelines (`/train`) are not decorated yet;
- one note on the merge request, updated in place by later runs of the same
  pipeline.

Scanner text is escaped and no secret appears.
