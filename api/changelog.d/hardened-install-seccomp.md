### Security: install commands run the sensor under its seccomp profile

- The API serves the sensor's seccomp profile at `GET /api/v1/sensors/install/seccomp.json` (public: the open-source release's file, no tenant data; rate limited per IP; `X-Content-SHA256`). It is the sensor release's `docker/seccomp/sensor.json`, embedded in the API.
- The docker run and Compose install commands download it, check its SHA-256 before the container starts, and run the container with it (`--security-opt seccomp=…` / `security_opt`); the Kubernetes manifest uses it as a `Localhost` profile (the snippet says how to put it on the nodes, and how to fall back); the Helm command sets `sensor.sandbox.seccompProfile=openctem`. Each scan task can then run network-confined, which jobs with a web scope need.
- The setup checklist explains the sensor's new `runtime.sandbox_network` check (sdk-go): confined, or the detected cause with its fix.
- **Upgrade note:** existing installs keep running as they are. To confine one, download the profile from the URL above and add it to the container's security options (or set the Helm value).
