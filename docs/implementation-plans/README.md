# Implementation Plans — Pending Work

Each file in this folder is a **ready-to-execute** spec for a CTEM task that is blocked on external resources (SDK choice, cloud credentials, design sign-off). When the blocker clears, the implementer should be able to open the file and start coding without re-deriving the design.

Contract per file:
- **Scope** — what ships, what does NOT ship.
- **External dependencies** — exactly which SDK, which credentials/secrets, which sandbox.
- **Data model** — the structs and DB tables the task touches.
- **Public interface** — function/method signatures, no bodies.
- **Resource mapping** — provider-native → internal model, as a table (this is the real risk).
- **Test plan** — unit + integration + sandbox smoke.
- **Rollout** — flag, migration order, backfill.
- **Open questions** — decisions deferred to the implementer, with pointers to who should answer.

## Index

| Task | File | Status | Blocker |
|---|---|---|---|
| #339 | [339-gcp-connector.md](./339-gcp-connector.md) | Pending | Needs GCP SDK + sandbox service-account JSON |
| #340 | [340-azure-connector.md](./340-azure-connector.md) | Pending | Needs Azure SDK + sandbox service-principal |
| #349 | [349-kubernetes-connector.md](./349-kubernetes-connector.md) | Pending | Needs client-go + dev kubeconfig |
| #350 | [350-git-host-connector.md](./350-git-host-connector.md) | Pending | Needs GitHub/GitLab/Bitbucket sandbox tokens |
| #363 | [363-per-tenant-kms.md](./363-per-tenant-kms.md) | Pending | Needs KMS backend decision |

All five share the same seam — `internal/app/connector/connector.go` for #339/#340/#349/#350, and a yet-to-be-created `pkg/crypto/envelope` for #363. Implementers should read the seam source before the plan so the plan's cross-references resolve.
