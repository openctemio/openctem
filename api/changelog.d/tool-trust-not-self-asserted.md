### Security: a sensor can no longer make its own tool "builtin" by claiming it

- A tool contract's `origin` is a sensor claim. The platform granted trust `builtin` and the capability's tier floor to any tool reporting `origin: builtin`, so an operator-installed tool with any name (including a catalog name the sensor does not ship, such as `zap`) could be classified builtin and run below T2.
- The claim is now honored only for the tools a released sensor compiles in (betterleaks, codeql, dnsx, httpx, katana, naabu, nuclei, nuclei-validate, semgrep, subfinder, trivy) and the SDK's `file-import`. Any other tool that claims it is unverified and T2, as an operator-installed tool is.
- Binding the claim to the signed release's descriptor digests is planned (RFC-060).
