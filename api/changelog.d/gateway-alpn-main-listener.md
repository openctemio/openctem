### Security: sensor ALPN routing only on the gateway's main HTTPS port

- The gateway's layer-4 sensor routing (`OPENCTEM_SENSOR_GATEWAY=alpn|passthrough`) now applies only to the main HTTPS listener (443). Before, it applied to every listener, so a TLS hello offering the sensor ALPN id on the console's port (8443) was passed to the API's sensor listener without the console site's client-network gate. The shared server settings moved to `api/deploy/gateway/servers.common`.
- **Upgrade note:** a deployment that copies the gateway files one by one (rather than the whole directory) also copies `servers.common`.
