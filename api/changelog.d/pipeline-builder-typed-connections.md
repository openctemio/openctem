### Added: typed connections in the pipeline builder

- Each step in the pipeline builder shows its capability, its tier and the port types it takes and gives, as served by `GET /api/v1/scans/stages`. A step without a contract (a tenant tool) says that it runs on the scan's targets and takes no data from earlier steps.
- Dragging a connection checks it as you drop. Incompatible ports, a loop, and derived targets into an intrusive (T2) step are refused with a plain reason. When the catalog has an adapter, the message offers **Insert step**, which adds the adapter step (for example an HTTP probe between subdomain discovery and a web crawl) and rewires the two.
- The builder checks the draft with `POST /api/v1/pipelines/verify` while you edit. It shows each problem on its step and blocks Save while the workflow has errors. A save the API refuses shows its issues on the steps.
- The connection rules and typed handles live in a shared `components/flow` kit for both canvases.
