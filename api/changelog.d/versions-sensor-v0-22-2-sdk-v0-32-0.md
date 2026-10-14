### Changed: install snippets pin sensor v0.22.2; SDK v0.32.0 is the latest

- The console's sensor install commands and the "update available" check point at sensor v0.22.2: one refused target no longer fails a whole scan task (the others run and the refused one is listed with its reason), and `host:port` targets are checked on their host.
- The newest SDK is v0.32.0, so a sensor built with an older SDK shows "SDK outdated". Sensor v0.22.2 is built with it; sensor v0.22.1 (an earlier sdk-go build) shows "SDK outdated" and "update available" together, both pointing at v0.22.2.
- `versions.yaml` names Helm chart 0.23.3, the newest published chart for v0.9.5 (it said 0.4.1).
