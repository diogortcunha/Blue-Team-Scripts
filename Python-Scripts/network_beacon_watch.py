#!/usr/bin/env python3

"""Summarize outbound connections and detect regular (beacon-like) connection patterns.

With ``--samples 1`` (default) this is a snapshot of the busiest destinations. With more
samples it records when *new* connections to each destination appear and flags destinations
contacted at very regular intervals (low jitter), which is typical of C2 beaconing.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter, defaultdict

from btcommon import Report, fmt_endpoint, is_loopback, is_private, is_unspecified, list_sockets, load_rules, make_parser

Key = tuple  # (remote_addr, remote_port, process)


def beacon_candidates(
    events: dict[Key, list[float]], sample_interval: float, min_events: int, max_jitter: float
) -> list[tuple[Key, float, float, int]]:
    """Return (key, mean_interval, jitter, n_events) for destinations contacted at regular intervals.

    Intervals close to the sampling interval are ignored: a destination that gets a new
    connection in every sample is just busy, and its timing cannot be measured.
    """
    results = []
    for key, times in events.items():
        if len(times) < min_events:
            continue
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(intervals)
        if mean < 2 * sample_interval:
            continue
        jitter = statistics.pstdev(intervals) / mean if mean else 1.0
        if jitter <= max_jitter:
            results.append((key, mean, jitter, len(times)))
    return sorted(results, key=lambda item: item[2])


def outbound(sockets, external_only: bool):
    """Outbound TCP connections and connected UDP sockets (Linux only: Windows does not
    expose the remote end of UDP sockets)."""
    for sock in sockets:
        if not sock.proto.startswith(("tcp", "udp")) or sock.listening or sock.state in {"TIME_WAIT", "TIME-WAIT", "CLOSE_WAIT"}:
            continue
        if is_unspecified(sock.remote_addr) or is_loopback(sock.remote_addr):
            continue
        if external_only and is_private(sock.remote_addr):
            continue
        yield sock


def main() -> int:
    parser = make_parser("Summarize outbound destinations and detect beaconing.")
    parser.add_argument("--limit", type=int, default=25, help="Max destinations to list (default: 25)")
    parser.add_argument("--samples", type=int, default=1, help="Number of samples to take (default: 1 = snapshot)")
    parser.add_argument("--interval", type=float, default=10.0, help="Seconds between samples (default: 10)")
    parser.add_argument("--external-only", action="store_true", help="Ignore private/link-local destinations")
    args = parser.parse_args()
    report = Report("network_beacon_watch", args, needs_admin=True)
    rules = load_rules("network_beacon_watch", args.rules)

    counts: Counter[str] = Counter()
    processes: dict[str, set[str]] = defaultdict(set)
    known_ports: dict[Key, set[int]] = defaultdict(set)
    events: dict[Key, list[float]] = defaultdict(list)
    start = time.monotonic()

    try:
        for sample in range(max(1, args.samples)):
            if sample:
                time.sleep(args.interval)
            sockets, error = list_sockets()
            if error:
                report.fail(error)
                return report.emit()
            now = time.monotonic() - start
            for sock in outbound(sockets, args.external_only):
                dest = fmt_endpoint(sock.remote_addr, sock.remote_port)
                if sock.proto.startswith("udp"):
                    dest = f"udp {dest}"
                if sample == 0:
                    counts[dest] += 1
                processes[dest].add(sock.process or str(sock.pid or "?"))
                key = (sock.remote_addr, sock.remote_port, f"{sock.process} (udp)" if sock.proto.startswith("udp") else sock.process)
                if sock.local_port not in known_ports[key]:
                    known_ports[key].add(sock.local_port)
                    if sample:
                        events[key].append(now)
    except KeyboardInterrupt:
        report.error("sampling interrupted; results are partial")

    threshold = rules.get("count_threshold", 10)
    for dest, count in counts.most_common(args.limit):
        procs = ", ".join(sorted(processes[dest]))
        data = {"destination": dest, "connections": count, "processes": sorted(processes[dest])}
        if count >= threshold:
            report.add("top destinations", "low", f"{dest}: {count} simultaneous connections ({procs})", **data)
        else:
            report.info("top destinations", f"{dest}: {count} ({procs})", **data)

    if args.samples > 1:
        candidates = beacon_candidates(events, args.interval, rules.get("min_events", 4), rules.get("max_jitter", 0.2))
        for (addr, port, proc), mean, jitter, n in candidates:
            report.add(
                "beaconing",
                "high",
                f"{fmt_endpoint(addr, port)} ({proc or '?'}) new connection every ~{mean:.0f}s "
                f"(jitter {jitter:.0%}, {n} connections)",
                destination=fmt_endpoint(addr, port),
                process=proc,
                mean_interval=round(mean, 1),
                jitter=round(jitter, 3),
                events=n,
            )
        if not candidates:
            report.info("beaconing", f"no regular connection pattern seen in {args.samples} samples")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
