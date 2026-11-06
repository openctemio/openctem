# How to run sensors against a platform behind a private CA

When the platform's TLS certificate is signed by a private certificate
authority (the built-in gateway in TLS mode `internal`, or your own CA), a
sensor host does not trust it, and a sensor stops with `signed by an
authority this host does not trust`. The platform solves this by itself once
it knows its CA: every install command in the console then carries the root's
SHA-256 (`SENSOR_CA_SHA256`), and the sensor fetches the CA from the platform
and trusts that root only.

This page is the single source for the private-CA setup. Related:
[pair a sensor](pair-a-sensor.md), the install commands
([architecture](../architecture/sensors.md), "CA"), the sensor's settings
([SENSOR_CA_SHA256](https://docs.openctem.io/sensors/settings/#SENSOR_CA_SHA256)).

## 1. Tell the platform its CA (operator, once)

Set `PLATFORM_CA_CERT_FILE` on the API to a PEM file with the CA
certificate(s) that sign the platform's certificate: the root, and the
intermediate if you want it shown. Public certificates only.

| Deployment | What to set |
|---|---|
| Compose stack (`deploy/docker-compose.yml`), gateway TLS mode `internal` | Nothing: the API already reads the gateway's exported root (`/ca/openctem-root-ca.crt`). |
| Your own compose or host | Mount the CA file read-only into the API container and set `PLATFORM_CA_CERT_FILE` to its path. |
| A platform with a publicly trusted certificate | Leave it unset: the commands stay as they are and the endpoint answers 404. |

The API reads the file at startup and again whenever it changes (a gateway
that exports its root after the API started, a rotation), so no restart is
needed. It logs each certificate's name and SHA-256 at startup. A file that
holds a **private key** is refused as a whole: the startup log says so, the
console shows no CA, and nothing of the file is served until it holds
certificates only. `SENSOR_CA_CERT_FILE`, the name the API used before, is
still read when `PLATFORM_CA_CERT_FILE` is unset (startup warns): rename it.

Check it: `curl -k https://<platform>/api/v1/sensors/platform-ca` returns
the PEM bundle (`application/x-pem-file`), and `openssl x509 -noout
-fingerprint -sha256` on the root shows the SHA-256 the console shows.

## 2. Add a sensor (administrator)

Open **Sensors → Add sensor**. Under the command, the panel names the
platform's CA certificates with their SHA-256 (root and intermediate), marks
the pinned root and links the bundle for download. Every command carries the
pin, so there is nothing to add by hand:

| Install | The pin in the command |
|---|---|
| docker run | `-e SENSOR_CA_SHA256=<root sha256>` (and the CA file installed under `/etc/openctem/certs`) |
| Docker Compose, Kubernetes, Linux service | `SENSOR_CA_SHA256` in the service's environment |
| Several sensors on one host (`sensors.sh`) | `./sensors.sh add NAME --api-url URL --ca-sha256 <root sha256>`; an existing kit sensor: `./sensors.sh set-ca NAME --sha256 <root sha256>` |
| Helm (a sensor's own install snippets) | `--set sensor.extraEnv[0].name=SENSOR_CA_SHA256 --set-string sensor.extraEnv[0].value=<root sha256>` |

A sensor started some other way gets the pin as `SENSOR_CA_SHA256`: 64 hex
digits (colons allowed), several separated by commas.

## How the sensor uses the pin

When the platform's chain is not trusted, the sensor fetches `GET
/api/v1/sensors/platform-ca` once without verifying the chain, and accepts
the bundle only if a certificate in it has a pinned SHA-256 **and** signs the
chain the server presented. It keeps only that certificate in its state
directory and trusts it from then on. Without a pin nothing is ever trusted
automatically.

## Security

- **The pin is the trust decision.** It travels in the command the
  administrator copies from the signed-in console, the same path as the
  pairing code. Anyone who can change that command could also change the
  platform URL, so the pin adds no new path for an attacker.
- **A man in the middle without the pin gets nowhere.** The endpoint is
  public and its answer is not secret; an attacker who answers the fetch
  with their own CA does not match the pin, and the sensor refuses it and
  keeps refusing the connection.
- **The endpoint serves certificates only.** It is unauthenticated,
  tenant-agnostic (one bundle for the whole instance, no organization data),
  rate limited per IP like the other public install files, cached for five
  minutes, and answers 404 when no CA is configured or the file was refused.
- **The sensor still verifies scan targets** with the system roots; the
  platform's CA is trusted for the platform connection.

## Rotating the root

1. Put the new root in `PLATFORM_CA_CERT_FILE` **next to** the old one. The
   console shows both roots and every new command pins both
   (`SENSOR_CA_SHA256=<old>,<new>`).
2. Re-pin existing sensors with both (`./sensors.sh set-ca NAME --sha256
   <old>,<new>`, or update the variable and restart).
3. Switch the platform's certificate to the new chain.
4. Remove the old root from the file and from the sensors' pins.

An expired root stays listed in the console but is no longer pinned.

## Air-gapped or no fetch wanted

Give the sensor the CA file instead: download it from the console (or copy
`PLATFORM_CA_CERT_FILE`) and set `SENSOR_CA_CERT_FILE` on the sensor host
(`./sensors.sh set-ca NAME --file FILE` in the kit). The docker run command
already installs the file and sets `SSL_CERT_DIR`.
