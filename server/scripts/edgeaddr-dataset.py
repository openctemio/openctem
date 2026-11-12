#!/usr/bin/env python3
"""Rebuild the address classifier's built-in dataset (pkg/domain/edgeaddr/dataset.json).

The platform never downloads these lists at run time (it talks only to its
sensors). A maintainer runs this script, reviews the diff and commits it:

    python3 -I server/scripts/edgeaddr-dataset.py fetch <empty dir>
    python3 -I server/scripts/edgeaddr-dataset.py build <that dir> server/pkg/domain/edgeaddr/dataset.json

`build` keeps the dataset's network-holder ("orgs") and host-suffix ("apexes")
entries and replaces its published ranges with the providers' own lists:

  - Amazon: ip-ranges.json, services CLOUDFRONT (edge), S3 and API_GATEWAY
    (cloud_shared: front ends many customers share) and GLOBALACCELERATOR
    (dedicated: each accelerator's addresses serve one customer, but they are
    provider space, never offered on a name's word alone);
  - Cloudflare ips-v4 / ips-v6, Fastly public-ip-list, Gcore public-ip-list,
    bunny.net edge server lists, Imperva integration ip list (edge);
  - Microsoft service tags, AzureFrontDoor.Frontend (edge);
  - Microsoft 365 endpoints (worldwide instance), service area Exchange: the
    shared mail front ends (Exchange Online, autodiscover, inbound and
    outbound mail protection) every customer's mail names point at
    (cloud_shared);
  - Google goog.json minus cloud.json: Google's own front ends, never a
    customer's address (cloud_shared);
  - Sucuri firewall ranges from its documentation (edge, listed below).

A shared range wins over a dedicated one that overlaps it (the classifier
answers "not shared" when any dedicated range holds an address), so a
dedicated prefix overlapping a shared one is dropped here.
"""

import ipaddress
import json
import pathlib
import sys
import urllib.request
from datetime import datetime, timezone

SOURCES = {
    "aws.json": ("GET", "https://ip-ranges.amazonaws.com/ip-ranges.json"),
    "cf4.txt": ("GET", "https://www.cloudflare.com/ips-v4"),
    "cf6.txt": ("GET", "https://www.cloudflare.com/ips-v6"),
    "fastly.json": ("GET", "https://api.fastly.com/public-ip-list"),
    "gcore.json": ("GET", "https://api.gcore.com/cdn/public-ip-list"),
    "bunny4.json": ("GET", "https://bunnycdn.com/api/system/edgeserverlist"),
    "bunny6.json": ("GET", "https://bunnycdn.com/api/system/edgeserverlist/ipv6"),
    "imperva.json": ("POST", "https://my.imperva.com/api/integration/v1/ips"),
    "goog.json": ("GET", "https://www.gstatic.com/ipranges/goog.json"),
    "cloud.json": ("GET", "https://www.gstatic.com/ipranges/cloud.json"),
    "m365.json": ("GET", "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"),
}
# Microsoft publishes the service tags under a dated file name: download it
# from https://www.microsoft.com/en-us/download/details.aspx?id=56519 and
# save it as azure.json in the same directory.

SUCURI = ["192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22", "2a02:fe80::/29"]

AWS_SERVICES = {
    "CLOUDFRONT": ("Amazon CloudFront", "edge"),
    "S3": ("Amazon S3", "cloud_shared"),
    "API_GATEWAY": ("Amazon API Gateway", "cloud_shared"),
    "GLOBALACCELERATOR": ("AWS Global Accelerator", "dedicated"),
}

# Network-holder names added to the dataset's own list (word prefixes).
EXTRA_ORGS = [
    {"match": "cloudfront", "provider": "Amazon CloudFront", "class": "edge"},
    {"match": "gcore", "provider": "Gcore", "class": "edge"},
    {"match": "g-core", "provider": "Gcore", "class": "edge"},
    {"match": "edgio", "provider": "Edgio", "class": "edge"},
    {"match": "cdnetworks", "provider": "CDNetworks", "class": "edge"},
    # Shared mail and SaaS providers: their networks serve every customer.
    {"match": "zoho", "provider": "Zoho", "class": "cloud_shared"},
    {"match": "proofpoint", "provider": "Proofpoint", "class": "cloud_shared"},
    {"match": "mimecast", "provider": "Mimecast", "class": "cloud_shared"},
    {"match": "barracuda", "provider": "Barracuda", "class": "cloud_shared"},
    {"match": "sendgrid", "provider": "SendGrid", "class": "cloud_shared"},
    {"match": "mailgun", "provider": "Mailgun", "class": "cloud_shared"},
    {"match": "sparkpost", "provider": "SparkPost", "class": "cloud_shared"},
    {"match": "salesforce", "provider": "Salesforce", "class": "cloud_shared"},
    {"match": "zendesk", "provider": "Zendesk", "class": "cloud_shared"},
    {"match": "atlassian", "provider": "Atlassian", "class": "cloud_shared"},
    {"match": "hubspot", "provider": "HubSpot", "class": "cloud_shared"},
]


def fetch(dest: pathlib.Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for name, (method, url) in SOURCES.items():
        data = b"resp_format=json" if method == "POST" else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URLs
            (dest / name).write_bytes(resp.read())
        print(f"fetched {name}")
    if not (dest / "azure.json").exists():
        print("azure.json missing: download the service tags file by hand (see the script header)")


def nets(values):
    out = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        out.append(ipaddress.ip_network(v if "/" in v else v + ("/128" if ":" in v else "/32"), strict=False))
    return out


def collapse(values):
    v4 = [n for n in values if n.version == 4]
    v6 = [n for n in values if n.version == 6]
    return list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))


def subtract(nets_a, nets_b):
    """nets_a minus nets_b, per family."""
    out = []
    for a in collapse(nets_a):
        parts = [a]
        for b in nets_b:
            if b.version != a.version:
                continue
            nxt = []
            for p in parts:
                if p.subnet_of(b):
                    continue
                if b.subnet_of(p):
                    nxt.extend(p.address_exclude(b))
                else:
                    nxt.append(p)
            parts = nxt
        out.extend(parts)
    return collapse(out)


def build(src: pathlib.Path, out: pathlib.Path) -> None:
    ranges = {}  # (provider, class) -> [networks]

    def add(provider, cls, values):
        ranges.setdefault((provider, cls), []).extend(values)

    aws = json.loads((src / "aws.json").read_text())
    for p in aws["prefixes"]:
        if p["service"] in AWS_SERVICES:
            add(*AWS_SERVICES[p["service"]], nets([p["ip_prefix"]]))
    for p in aws["ipv6_prefixes"]:
        if p["service"] in AWS_SERVICES:
            add(*AWS_SERVICES[p["service"]], nets([p["ipv6_prefix"]]))

    add("Cloudflare", "edge", nets((src / "cf4.txt").read_text().split() + (src / "cf6.txt").read_text().split()))
    fastly = json.loads((src / "fastly.json").read_text())
    add("Fastly", "edge", nets(fastly["addresses"] + fastly.get("ipv6_addresses", [])))
    gcore = json.loads((src / "gcore.json").read_text())
    add("Gcore", "edge", nets(gcore["addresses"] + gcore.get("addresses_v6", [])))
    add("bunny.net", "edge", nets(json.loads((src / "bunny4.json").read_text()) + json.loads((src / "bunny6.json").read_text())))
    imperva = json.loads((src / "imperva.json").read_text())
    add("Imperva", "edge", nets(imperva["ipRanges"] + imperva.get("ipv6Ranges", [])))
    add("Sucuri", "edge", nets(SUCURI))

    azure = json.loads((src / "azure.json").read_text())
    for v in azure["values"]:
        if v["name"] == "AzureFrontDoor.Frontend":
            add("Azure Front Door", "edge", nets(v["properties"]["addressPrefixes"]))

    m365 = json.loads((src / "m365.json").read_text())
    add("Microsoft 365", "cloud_shared", nets([ip for e in m365 if e.get("serviceArea") == "Exchange" for ip in e.get("ips", [])]))

    goog = json.loads((src / "goog.json").read_text())
    cloud = json.loads((src / "cloud.json").read_text())
    pick = lambda d: nets([p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in d["prefixes"]])  # noqa: E731
    add("Google", "cloud_shared", subtract(pick(goog), pick(cloud)))

    shared_all = [n for (prov, cls), ns in ranges.items() if cls != "dedicated" for n in ns]
    entries = []
    order = {"edge": 0, "saas_hosting": 1, "cloud_shared": 2, "dedicated": 3}
    for (prov, cls), ns in sorted(ranges.items(), key=lambda kv: (order[kv[0][1]], kv[0][0])):
        ns = collapse(ns)
        if cls == "dedicated":
            ns = [n for n in ns if not any(n.version == s.version and n.overlaps(s) for s in shared_all)]
        entries.append({"provider": prov, "class": cls, "prefixes": [str(n) for n in ns]})

    old = json.loads(out.read_text())
    orgs = old["orgs"]
    known = {o["match"] for o in orgs}
    # Specific names first: "cloudfront" must win over the generic "amazon".
    orgs = [o for o in EXTRA_ORGS if o["match"] not in known] + orgs
    dataset = {
        "version": datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".1",
        "ranges": entries,
        "orgs": orgs,
        "apexes": old["apexes"],
    }
    out.write_text(json.dumps(dataset, indent=1) + "\n")
    for e in entries:
        print(f"{e['provider']:24} {e['class']:13} {len(e['prefixes'])}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "fetch":
        fetch(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "build":
        build(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
    else:
        sys.exit(__doc__)
