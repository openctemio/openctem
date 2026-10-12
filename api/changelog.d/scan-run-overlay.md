### Added: a workflow scan run shows its steps as a graph

- The scan run panel shows a workflow run as a graph. Each step shows its status, the capability and tool it ran, how many targets it took in and was handed, the reasons targets were left out, its findings and its error. The graph is read-only and refreshes while the run is live.
- The graph is built from the run's own step records (which keep their name, tool and capability after the workflow changes) and from `GET /pipeline-runs/{id}/stages`. The workflow's dependencies draw the edges. Nothing is computed in the browser.
- The run's stage lanes take their labels from the capability catalog the API serves, instead of a copy kept in the web app.
