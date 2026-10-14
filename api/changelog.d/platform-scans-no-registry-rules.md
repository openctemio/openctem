### Security: platform scans never fetch registry SAST rules

- A platform job (a scan run on platform-operated sensors) whose tool is semgrep is refused when it is created. semgrep fetches registry rules when a sensor has no managed rules, and the registry rules licence does not allow providing them as a service. Platform scans run static analysis with opengrep and the OpenCTEM rules pack.
- A platform-operated sensor's content policy never carries registry rulesets. Its pinned version and maximum ages stay. A tenant's own sensors still get the rulesets their tenant chose, which they fetch under the tenant's licence.
