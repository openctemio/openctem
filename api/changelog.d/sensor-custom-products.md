### Added: organizations' own sensor products and an SDK minimum

- A sensor is judged by what it declares (protocol, SDK, capabilities) against ranges the platform owns, whatever its product (RFC-037 §13, `docs/architecture/sensor-compatibility.md`).
- New `sdk.min` in `versions.yaml` (empty for now): a sensor of any product built with an older sdk-go is degraded with the critical reason `sdk_unsupported`; `sdk_status` gains `unsupported`. SDK checks apply only to sensors built with sdk-go.
- An organization records the latest and minimum release of a sensor product it builds itself: `GET /api/v1/sensors/custom-products` (`sensors:read`), `PUT` and `DELETE /api/v1/sensors/custom-products/{product}` (`sensors:write`, audited, at most 50). Its sensors of that product then get "update available" and "unsupported" verdicts, for that organization only. Names starting with `openctemio-` and products the platform lists are refused. Migration `002913_tenant_sensor_products` (new table).
- A custom product without a recorded release line keeps only the SDK and protocol verdicts.
- **Upgrade note:** nothing to do.
