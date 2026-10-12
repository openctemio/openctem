### Added: sensor protocol v3 contract (gRPC + mTLS, Connect/HTTPS fallback)

- RFC-059 and the `openctem.sensor.v3.SensorService` proto (`api/proto`), with the generated Go code in `api/pkg/sensorproto/v3`. Nothing serves it yet; protocol v2 is unchanged.
- API CI runs `buf lint`, `buf breaking` against the base branch and a generated-code drift check (`make proto-check`).
