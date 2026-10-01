# Protocol v1 compatibility harness

Sensors and SDK builds already deployed in the field speak **protocol v1**
(`/api/v1/agent/*`), which is frozen (RFC-023 §9.2, rule C8). This module runs
the **last released** `sdk-go` against an API build over real HTTP and fails if
any step a deployed sensor performs stops working:

| Step | SDK call |
|---|---|
| connection test | `client.TestConnection` |
| heartbeat | `client.SendHeartbeat` |
| push findings and assets | `client.PushFindings` |
| command lifecycle | `PollCommands` → `AcknowledgeCommand` → `StartCommand` → `ReportCommandProgress` → `CompleteCommand` |
| suppression rules | `client.GetSuppressions` |
| key renewal | `platform.PlatformClient.RenewKey`, then a heartbeat with the new key |

`scripts/compat-v1.sh` provisions a tenant, a sensor key and a queued command
through the management API, runs this module, then checks the platform recorded
the command as completed and the sensor as online. CI runs it in the
*Protocol v1 Compatibility* job.

Run locally against a migrated database and a running API:

```bash
COMPAT_API_URL=http://127.0.0.1:8080 \
DATABASE_URL=postgres://openctem:secret@127.0.0.1:5432/openctem?sslmode=disable \
BOOTSTRAP_TENANT_BIN=./bin/bootstrap-tenant \
scripts/compat-v1.sh
```

## The SDK pin is deliberate

`go.mod` pins the newest **released** `sdk-go` tag, never `main` and never
`latest`: the point is to test what customers actually run. Bump it by hand
when a new SDK version is released (and keep the previous one passing until
the platform's minimum sensor protocol retires it). Do not let automated
dependency updates move it.

If a change to the API makes this harness fail, the change broke deployed
sensors: fix the API, not the harness. Only the provisioning calls in
`scripts/compat-v1.sh` (management API) may be updated alongside the API.
