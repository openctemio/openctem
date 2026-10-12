### Added: the organization's layer of its scan tools' HTTP settings (RFC-060 §4.1)

- Settings > Security can set a User-Agent for the organization's scan tools (`tool_http_user_agent`) and refuse tools that skip TLS verification (`forbid_tool_insecure_tls`).
- The platform puts them in every scan job it hands a sensor (`http_policy`), as they are at delivery. It replaces any value a command's creator set.
- They only narrow: the sensor's local policy decides first (sdk-go `core.OrgHTTPPolicy`).
- Allowing insecure TLS again is audited at high severity.
- A delivery fails (fail closed) when the organization's policy cannot be read.
- Sensors before the matching sdk-go release ignore the field.
