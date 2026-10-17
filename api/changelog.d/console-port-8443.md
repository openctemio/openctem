### Changed: the platform console's site defaults to port 8443

- In port mode (`OPENCTEM_ADMIN_SITE=port`, the Compose default) the console's site is `https://<OPENCTEM_HOSTNAME>:8443`; change it with `OPENCTEM_ADMIN_PORT` if the port is taken. The gateway refuses a console port equal to 80, 443 or `GATEWAY_HTTPS_PORT`, and one out of range.
- `setup.sh` sets each console setting on its own: `--admin-site port|host|off`, `--admin-host`, `--admin-port`, `--admin-cidrs`, `--admin-public`, and recommends a host name of its own for production.
- `OPENCTEM_ADMIN_BIND` (optional) publishes the console port on one interface only, such as a private or VPN address: a published container port is not filtered by the host firewall.
