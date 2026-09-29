#!/usr/bin/env python3

"""Show listening ports (and optionally connections) and flag unusual listeners."""

from __future__ import annotations

from btcommon import Report, fmt_endpoint, handle_baseline, is_loopback, is_unspecified, list_sockets, load_rules, make_parser


def main() -> int:
    parser = make_parser("Inspect listening ports and connections.", baseline=True)
    parser.add_argument("--connections", action="store_true", help="Also list established/active connections")
    args = parser.parse_args()
    report = Report("port_watch", args, needs_admin=True)

    suspicious_ports = set(load_rules("port_watch", args.rules).get("suspicious_ports", []))
    sockets, error = list_sockets()
    if error:
        report.fail(error)
        return report.emit()

    listeners: dict[str, str] = {}
    for sock in sorted(sockets, key=lambda s: (s.proto, s.local_port or 0)):
        if not sock.listening:
            continue
        process = f"{sock.process or '?'} (pid {sock.pid})" if sock.pid else (sock.process or "?")
        exposed = not is_loopback(sock.local_addr)
        # Keyed without pid so restarts of the same service do not show up as changes.
        listeners[f"{sock.proto} {fmt_endpoint(sock.local_addr, sock.local_port)}"] = sock.process
        message = f"{sock.proto:<4} {fmt_endpoint(sock.local_addr, sock.local_port):<24} {process}"
        data = {"proto": sock.proto, "address": sock.local_addr, "port": sock.local_port, "pid": sock.pid, "process": sock.process}
        if sock.local_port in suspicious_ports and exposed:
            scope = "all interfaces" if is_unspecified(sock.local_addr) else sock.local_addr
            report.add("listening", "medium", f"{message} <- port often used by backdoors/C2, exposed on {scope}", **data)
        else:
            report.info("listening", message, **data)

    if args.connections:
        for sock in sockets:
            if sock.listening or sock.state in {"TIME_WAIT", "TIME-WAIT"}:
                continue
            report.info(
                "connections",
                f"{sock.proto:<4} {sock.state:<12} {fmt_endpoint(sock.local_addr, sock.local_port)} -> "
                f"{fmt_endpoint(sock.remote_addr, sock.remote_port)} {sock.process or ''} {sock.pid or ''}".rstrip(),
                proto=sock.proto,
                state=sock.state,
                remote=fmt_endpoint(sock.remote_addr, sock.remote_port),
                pid=sock.pid,
                process=sock.process,
            )

    handle_baseline(report, listeners, check="new listeners", removed_severity="info", changed_severity="low")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
