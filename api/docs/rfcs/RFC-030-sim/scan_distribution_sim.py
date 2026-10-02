#!/usr/bin/env python3
"""Discrete-event simulation for RFC-030 (scan work distribution).

Compares how OpenCTEM distributes scan work today with the proposed
plan -> chunks -> lease model. Standard library only; deterministic seeds.

    python3 scan_distribution_sim.py            # all scenarios, 20 seeds each

Model
-----
* A sensor has `slots` (concurrent scanner processes; the deployed daemon
  hard-codes 5) and a `speed` multiplier (2.0 = takes twice as long).
* A target costs `cost` slot-seconds, drawn from a log-normal per tool
  (heavy-tailed: a few hosts/repos take far longer than the median).
* A chunk (command) runs on one slot; its duration is the sum of its
  targets' costs times the sensor's speed, plus a fixed per-command overhead
  (process start, template load, result upload).
* A sensor can die at time `dies_at`: everything it holds stops.

Policies
--------
current_zoned     today's zoned trigger (internal/app/scan/zones.go): fixed
                  batches of targets_per_job, each PINNED at trigger time to
                  the sensor with the fewest active commands (capacity and
                  speed ignored); a pinned command is never moved. Commands
                  on a dead sensor never finish; the run is reaped at its
                  timeout (default 1 h).
current_unzoned   today's unzoned trigger: ONE command carrying every target;
                  the first sensor to poll takes it.
pull_fixed        phase 1: same fixed batches, NOT pinned; any free slot of a
                  capable sensor claims the next one; a lease that is not
                  renewed (dead sensor) expires after LEASE_TTL and the chunk
                  is re-queued.
pull_adaptive     phase 2: chunks are cut at claim time from the scan's
                  remaining targets, sized to a time budget for the claiming
                  sensor (measured per-target cost x sensor speed), shrinking
                  towards the end (guided self-scheduling) so no straggler
                  holds the run; leases as above.

Fairness policies for the multi-tenant scenario: `fifo` (global
priority, created_at — today's poll ORDER BY) vs `drr` (deficit round robin
over tenants, then scans, by slot-seconds).
"""

from __future__ import annotations

import heapq
import math
import random
import statistics
from dataclasses import dataclass, field

OVERHEAD = 8.0          # seconds per command: process start, templates, upload
LEASE_TTL = 120.0       # seconds without renewal before a lease is re-queued
RUN_TIMEOUT = 3600.0    # scan.DefaultScanTimeoutSeconds
MAX_ZONE_JOBS = 1000    # maxZoneJobsPerRun

TOOLS = {
    # median slot-seconds per target, log-normal sigma (tail weight)
    "nuclei": (20.0, 1.0),
    "trivy": (45.0, 1.2),
    "betterleaks": (25.0, 1.5),
}


@dataclass
class Sensor:
    name: str
    slots: int
    speed: float = 1.0
    dies_at: float = math.inf
    busy: float = 0.0          # slot-seconds spent on useful work
    alive_slots: float = 0.0   # slot-seconds available while alive


@dataclass
class Scan:
    sid: str
    tenant: str
    tool: str
    costs: list[float]
    submit: float = 0.0
    done_targets: int = 0
    finished_at: float | None = None
    cursor: int = 0            # next target index (adaptive planner)
    skipped: int = 0           # targets the policy never dispatches
    done_by_timeout: int = 0   # targets finished before the run timeout


@dataclass(order=True)
class Ev:
    t: float
    seq: int
    kind: str = field(compare=False)
    data: tuple = field(compare=False, default=())


def draw_costs(rng: random.Random, tool: str, n: int) -> list[float]:
    med, sigma = TOOLS[tool]
    return [med * math.exp(rng.gauss(0.0, sigma)) for _ in range(n)]


class Sim:
    def __init__(self, sensors, scans, policy, batch=50, fairness="fifo",
                 budget=300.0, horizon=48 * 3600.0):
        self.sensors = sensors
        self.scans = {s.sid: s for s in scans}
        self.policy = policy
        self.batch = batch
        self.fairness = fairness
        self.budget = budget
        self.horizon = horizon
        self.q: list[Ev] = []
        self.seq = 0
        self.now = 0.0
        self.free = {s.name: s.slots for s in sensors}
        self.queue: list[dict] = []           # pending chunks (pull policies)
        self.pinned: dict[str, list[dict]] = {s.name: [] for s in sensors}
        # prior per tool (catalog): the log-normal mean; learned per
        # (tool, sensor) from finished chunks, EWMA of seconds per target
        self.prior = {t: TOOLS[t][0] * math.exp(TOOLS[t][1] ** 2 / 2) for t in TOOLS}
        self.est: dict[tuple[str, str], float] = {}
        self.usage: dict[str, tuple[float, float]] = {}   # tenant -> (decayed slot-s, at)
        self.rejected: list[str] = []
        self.running: dict[int, dict] = {}
        self.cid = 0
        self.last_done = 0.0

    # -- event plumbing --------------------------------------------------
    def push(self, t, kind, *data):
        self.seq += 1
        heapq.heappush(self.q, Ev(t, self.seq, kind, data))

    def sensor(self, name) -> Sensor:
        return next(s for s in self.sensors if s.name == name)

    def alive(self, s: Sensor) -> bool:
        return self.now < s.dies_at

    # -- planning --------------------------------------------------------
    def submit(self, sc: Scan):
        n = len(sc.costs)
        if self.policy == "current_unzoned":
            if sc.tool != "nuclei":
                # applyTargetsToPayload sets target=targets[0]; the sensor
                # prefers `target`, so only the first target is ever scanned
                sc.skipped = n - 1
                n = 1
            self.queue.append(self.chunk(sc, 0, n))
        elif self.policy in ("current_zoned", "pull_fixed"):
            b = max(1, self.batch)
            chunks = [self.chunk(sc, i, min(i + b, n)) for i in range(0, n, b)]
            if self.policy == "current_zoned" and len(chunks) > MAX_ZONE_JOBS:
                self.rejected.append(sc.sid)  # TOO_MANY_JOBS: trigger refused
                return
            if self.policy == "current_zoned":
                active = {s.name: len(self.pinned[s.name]) for s in self.sensors
                          if self.alive(s)}
                for c in chunks:      # least active commands, capacity ignored
                    name = min(active, key=lambda k: (active[k], k))
                    active[name] += 1
                    self.pinned[name].append(c)
            else:
                self.queue.extend(chunks)
        # pull_adaptive: nothing is materialised; chunks are cut at claim time
        self.dispatch()

    def chunk(self, sc: Scan, lo: int, hi: int) -> dict:
        self.cid += 1
        return {"id": self.cid, "scan": sc.sid, "lo": lo, "hi": hi, "attempt": 0}

    # -- adaptive chunk size (RFC-030 §5.2) ------------------------------
    def adaptive_size(self, sc: Scan, s: Sensor) -> int:
        remaining = len(sc.costs) - sc.cursor
        c_hat = self.est.get((sc.tool, s.name), self.prior[sc.tool])
        by_budget = max(1, int((self.budget - OVERHEAD) / max(c_hat, 1e-6)))
        live_slots = sum(x.slots for x in self.sensors if self.alive(x))
        gss = max(1, math.ceil(remaining / (2 * max(1, live_slots))))  # guided self-scheduling
        return max(1, min(by_budget, gss, remaining))

    # -- selection ---------------------------------------------------------
    def too_slow_for_tail(self, sc: Scan, s: Sensor) -> bool:
        """Near the end of a scan, a sensor much slower than the fastest live
        one leaves the last targets to faster sensors instead of becoming the
        straggler (RFC-030 section 5.2, tail rule)."""
        live = [x for x in self.sensors if self.alive(x)]
        mine = self.est.get((sc.tool, s.name), self.prior[sc.tool])
        best = min(self.est.get((sc.tool, x.name), self.prior[sc.tool]) for x in live)
        remaining = len(sc.costs) - sc.cursor
        fast_slots = sum(x.slots for x in live
                         if self.est.get((sc.tool, x.name), self.prior[sc.tool]) <= 1.5 * best)
        return mine > 1.5 * best and remaining <= 2 * fast_slots

    def next_chunk(self, s: Sensor):
        if self.policy == "current_zoned":
            return self.pinned[s.name].pop(0) if self.pinned[s.name] else None
        if self.policy == "pull_adaptive":
            cands = [sc for sc in self.scans.values()
                     if sc.submit <= self.now and sc.cursor < len(sc.costs)]
            requeued = [c for c in self.queue]
            if requeued:                      # retries go first
                return self.pick(requeued, s, from_queue=True)
            cands = [sc for sc in cands if not self.too_slow_for_tail(sc, s)]
            if not cands:
                return None
            sc = self.pick_scan(cands)
            n = self.adaptive_size(sc, s)
            c = self.chunk(sc, sc.cursor, sc.cursor + n)
            sc.cursor += n
            return c
        return self.pick(self.queue, s, from_queue=True) if self.queue else None

    HALF_LIFE = 900.0

    def used(self, tenant):
        v, at = self.usage.get(tenant, (0.0, self.now))
        return v * 0.5 ** ((self.now - at) / self.HALF_LIFE)

    def charge(self, tenant, slot_seconds):
        self.usage[tenant] = (self.used(tenant) + slot_seconds, self.now)

    def pick(self, chunks, s, from_queue):
        if self.fairness == "drr":
            tenants = {self.scans[c["scan"]].tenant for c in chunks}
            t = min(tenants, key=lambda x: self.used(x))
            c = next(c for c in chunks if self.scans[c["scan"]].tenant == t)
        else:
            c = chunks[0]
        if from_queue:
            self.queue.remove(c)
        return c

    def pick_scan(self, cands):
        if self.fairness == "drr":
            return min(cands, key=lambda sc: (self.used(sc.tenant), sc.submit))
        return min(cands, key=lambda sc: sc.submit)

    def dispatch(self):
        for s in self.sensors:
            if not self.alive(s):
                continue
            while self.free[s.name] > 0:
                c = self.next_chunk(s)
                if c is None:
                    break
                self.start(s, c)

    def start(self, s: Sensor, c: dict):
        sc = self.scans[c["scan"]]
        dur = OVERHEAD + s.speed * sum(sc.costs[c["lo"]:c["hi"]])
        self.free[s.name] -= 1
        c["sensor"], c["t0"] = s.name, self.now
        self.running[c["id"]] = c
        # fairness accounting charges the expected cost when work is handed out
        self.charge(sc.tenant, dur)
        if self.now + dur <= s.dies_at:
            self.push(self.now + dur, "done", c["id"])
        elif self.policy in ("pull_fixed", "pull_adaptive"):
            # the lease stops being renewed at death and expires LEASE_TTL later
            self.push(s.dies_at + LEASE_TTL, "lease_expired", c["id"])

    # -- run -------------------------------------------------------------
    def run(self):
        for sc in sorted(self.scans.values(), key=lambda x: x.submit):
            self.push(sc.submit, "submit", sc.sid)
        for s in self.sensors:
            if s.dies_at < math.inf:
                self.push(s.dies_at, "death", s.name)
        while self.q:
            ev = heapq.heappop(self.q)
            if ev.t > self.horizon:
                break
            self.now = ev.t
            if ev.kind == "submit":
                self.submit(self.scans[ev.data[0]])
            elif ev.kind == "done":
                self.finish(ev.data[0])
            elif ev.kind == "lease_expired":
                c = self.running.pop(ev.data[0], None)
                if c:
                    c["attempt"] += 1
                    self.queue.insert(0, {k: v for k, v in c.items() if k not in ("sensor", "t0")})
            elif ev.kind == "death":
                pass  # pull policies: leases expire on their own (lease_expired)
            self.dispatch()
        return self.report()

    def finish(self, cid):
        c = self.running.pop(cid, None)
        if c is None:
            return
        s = self.sensor(c["sensor"])
        sc = self.scans[c["scan"]]
        n = c["hi"] - c["lo"]
        dur = self.now - c["t0"]
        s.busy += dur
        self.last_done = self.now
        self.free[s.name] += 1
        sc.done_targets += n
        if self.now - sc.submit <= RUN_TIMEOUT:
            sc.done_by_timeout += n
        # learn seconds per target for (tool, sensor): only what a real
        # server sees -- the chunk's wall time and its target count
        per_target = (dur - OVERHEAD) / max(n, 1)
        key = (sc.tool, s.name)
        self.est[key] = 0.7 * self.est.get(key, self.prior[sc.tool]) + 0.3 * per_target
        if sc.done_targets + sc.skipped >= len(sc.costs) and sc.finished_at is None:
            sc.finished_at = self.now

    def report(self):
        out = {}
        total = sum(len(sc.costs) for sc in self.scans.values())
        done = sum(sc.done_targets for sc in self.scans.values())
        ends = [sc.finished_at for sc in self.scans.values() if sc.finished_at is not None]
        makespan = max(ends) if len(ends) == len(self.scans) else math.inf
        end = makespan if makespan < math.inf else self.last_done
        cap = sum(s.slots * max(0.0, min(end, s.dies_at)) for s in self.sensors)
        busy = sum(s.busy for s in self.sensors)
        out["makespan_s"] = makespan
        out["coverage_in_timeout"] = self.coverage_at(RUN_TIMEOUT)
        out["coverage"] = done / total if total else 1.0
        out["utilisation"] = busy / cap if cap else 0.0
        out["per_scan_latency_s"] = {sid: (sc.finished_at - sc.submit) if sc.finished_at else math.inf
                                     for sid, sc in self.scans.items()}
        out["rejected"] = list(self.rejected)
        return out

    def coverage_at(self, t):
        # approximation: a scan finished within the timeout covers everything,
        # otherwise count completed targets (runs are reaped at the timeout)
        # targets whose results were in before the run's 1 h timeout reaped it
        total = sum(len(sc.costs) for sc in self.scans.values())
        ok = sum(sc.done_by_timeout for sc in self.scans.values())
        return ok / total if total else 1.0


# -------------------------------------------------------------------------
# scenarios
# -------------------------------------------------------------------------

def fleet(kind):
    if kind == "hetero":
        return [Sensor("s1", 5, 1.0), Sensor("s2", 5, 1.0), Sensor("s3", 2, 1.0), Sensor("s4", 5, 2.5)]
    if kind == "hetero_death":
        return [Sensor("s1", 5, 1.0), Sensor("s2", 5, 1.0, dies_at=600.0), Sensor("s3", 2, 1.0), Sensor("s4", 5, 2.5)]
    raise ValueError(kind)


def run(policy, scenario, seed, batch=50, fairness="fifo"):
    rng = random.Random(seed)
    if scenario in ("big_nuclei", "big_nuclei_death"):
        sensors = fleet("hetero" if scenario == "big_nuclei" else "hetero_death")
        scans = [Scan("A", "t1", "nuclei", draw_costs(rng, "nuclei", 1000))]
    elif scenario == "repos":
        sensors = fleet("hetero")
        scans = [Scan("R", "t1", "betterleaks", draw_costs(rng, "betterleaks", 1000))]
    elif scenario == "multitenant":
        sensors = fleet("hetero")
        scans = [Scan("A", "t1", "nuclei", draw_costs(rng, "nuclei", 1500), submit=0.0),
                 Scan("B", "t2", "nuclei", draw_costs(rng, "nuclei", 50), submit=120.0),
                 Scan("C", "t3", "nuclei", draw_costs(rng, "nuclei", 200), submit=300.0)]
    else:
        raise ValueError(scenario)
    return Sim(sensors, scans, policy, batch=batch, fairness=fairness).run()


def agg(policy, scenario, seeds=20, **kw):
    rs = [run(policy, scenario, s, **kw) for s in range(seeds)]
    fin = [r["makespan_s"] for r in rs if r["makespan_s"] < math.inf]
    med = statistics.median(fin) if len(fin) == len(rs) else math.inf
    return {
        "makespan_min": med / 60 if med < math.inf else math.inf,
        "finished_runs": f"{len(fin)}/{len(rs)}",
        "util": statistics.mean(r["utilisation"] for r in rs),
        "cov_1h": statistics.mean(r["coverage_in_timeout"] for r in rs),
        "cov": statistics.mean(r["coverage"] for r in rs),
        "lat": {k: statistics.median(r["per_scan_latency_s"][k] for r in rs) / 60
                for k in rs[0]["per_scan_latency_s"]},
        "rejected": sum(1 for r in rs if r["rejected"]),
    }


def fmt(x):
    return "inf" if x == math.inf else f"{x:6.1f}"


def main():
    rows = []
    for scenario, configs in [
        ("big_nuclei", [("current_unzoned", {}), ("current_zoned", {"batch": 1}),
                        ("current_zoned", {"batch": 50}), ("pull_fixed", {"batch": 50}),
                        ("pull_fixed", {"batch": 10}), ("pull_adaptive", {})]),
        ("big_nuclei_death", [("current_zoned", {"batch": 50}), ("pull_fixed", {"batch": 50}),
                              ("pull_adaptive", {})]),
        ("repos", [("current_unzoned", {}), ("pull_fixed", {"batch": 1}),
                   ("pull_fixed", {"batch": 20}), ("pull_adaptive", {})]),
        ("multitenant", [("current_zoned", {"batch": 50}), ("pull_fixed", {"batch": 50}),
                         ("pull_adaptive", {"fairness": "fifo"}), ("pull_adaptive", {"fairness": "drr"})]),
    ]:
        print(f"\n## {scenario}")
        print(f"{'policy':<28}{'makespan(min)':>14}{'finished':>10}{'util':>7}{'done<=1h':>9}{'scanned':>8}  per-scan latency (min)")
        for policy, kw in configs:
            a = agg(policy, scenario, **kw)
            label = policy + ("" if not kw else " " + ",".join(f"{k}={v}" for k, v in kw.items()))
            lat = " ".join(f"{k}={fmt(v).strip()}" for k, v in a["lat"].items())
            rej = f"  (trigger refused in {a['rejected']}/20)" if a["rejected"] else ""
            print(f"{label:<28}{fmt(a['makespan_min']):>14}{a['finished_runs']:>10}{a['util']:7.2f}{a['cov_1h']:9.2f}{a['cov']:8.3f}  {lat}{rej}")
            rows.append((scenario, label, a))
    return rows


if __name__ == "__main__":
    main()
