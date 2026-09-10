#!/usr/bin/env python3
"""Low-overhead connection collector for X-UI dokodemo-door inbounds."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import signal
import sqlite3
import time
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


TCP_ESTABLISHED = "01"


@dataclass(frozen=True)
class Connection:
    local_port: int
    remote_ip: str


def decode_proc_address(value: str, ipv6: bool) -> str:
    raw = bytes.fromhex(value)
    if ipv6:
        raw = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
        address = ipaddress.IPv6Address(raw)
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    return str(ipaddress.IPv4Address(raw[::-1]))


def parse_proc_net_tcp(text: str, ipv6: bool = False) -> list[Connection]:
    connections: list[Connection] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != TCP_ESTABLISHED:
            continue
        local_address, local_port = fields[1].split(":")
        remote_address, _remote_port = fields[2].split(":")
        if int(remote_address, 16) == 0:
            continue
        connections.append(
            Connection(
                local_port=int(local_port, 16),
                remote_ip=decode_proc_address(remote_address, ipv6),
            )
        )
    return connections


def read_connections(proc_root: Path) -> list[Connection]:
    result: list[Connection] = []
    for name, ipv6 in (("tcp", False), ("tcp6", True)):
        path = proc_root / name
        try:
            result.extend(parse_proc_net_tcp(path.read_text(encoding="ascii"), ipv6))
        except FileNotFoundError:
            pass
    return result


def read_xui_ports(db_path: Path) -> dict[int, dict[str, object]]:
    uri = f"file:{db_path}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        rows = connection.execute(
            "SELECT id, port, remark, protocol, enable FROM inbounds WHERE enable = 1"
        ).fetchall()
    finally:
        connection.close()
    return {
        int(port): {
            "id": int(inbound_id),
            "remark": remark or "",
            "protocol": protocol or "unknown",
        }
        for inbound_id, port, remark, protocol, _enable in rows
    }


def open_state_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS sightings (
            port INTEGER NOT NULL,
            ip TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            samples INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (port, ip)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT PRIMARY KEY,
            location TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            region TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            isp TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def lookup_ip_location(ip: str, endpoint: str, timeout: float) -> dict[str, str]:
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {"location": "内网地址", "country": "", "region": "", "city": "", "isp": ""}
    request = urllib.request.Request(
        endpoint.format(ip=ip),
        headers={"Accept": "application/json", "User-Agent": "xui-network-console/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("success") is False:
        raise ValueError(str(payload.get("message") or "geolocation lookup failed"))
    country = str(payload.get("country") or "")
    region = str(payload.get("region") or "")
    city = str(payload.get("city") or "")
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    isp = str(connection.get("isp") or connection.get("org") or "")
    asn = str(connection.get("asn") or "").upper()
    asn = asn[2:] if asn.startswith("AS") else asn
    isp_key = isp.lower()
    if asn in {"9808", "56046", "24400"} or "china mobile" in isp_key:
        isp = "中国移动"
    elif asn in {"4134", "4812", "4809"} or "china telecom" in isp_key:
        isp = "中国电信"
    elif asn in {"4837", "9929", "17621"} or "china unicom" in isp_key:
        isp = "中国联通"
    location = " · ".join(part for part in (country, region, city, isp) if part) or "未知"
    return {"location": location, "country": country, "region": region, "city": city, "isp": isp}


def resolve_one_location(state_db: Path, endpoint: str, timeout: float, retry_seconds: int) -> bool:
    state = open_state_db(state_db)
    now = int(time.time())
    try:
        row = state.execute(
            """
            SELECT DISTINCT sightings.ip
            FROM sightings
            LEFT JOIN geo_cache ON geo_cache.ip = sightings.ip
            WHERE geo_cache.ip IS NULL OR (geo_cache.status = 'failed' AND geo_cache.updated_at < ?)
            ORDER BY sightings.last_seen DESC
            LIMIT 1
            """,
            (now - retry_seconds,),
        ).fetchone()
        if not row:
            return False
        ip = str(row[0])
        try:
            result = lookup_ip_location(ip, endpoint, timeout)
            values = (ip, result["location"], result["country"], result["region"], result["city"], result["isp"], "ok", now)
        except (OSError, ValueError, json.JSONDecodeError):
            values = (ip, "归属地查询失败", "", "", "", "", "failed", now)
        state.execute(
            """
            INSERT INTO geo_cache(ip, location, country, region, city, isp, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                location=excluded.location, country=excluded.country, region=excluded.region,
                city=excluded.city, isp=excluded.isp, status=excluded.status, updated_at=excluded.updated_at
            """,
            values,
        )
        state.commit()
        return True
    finally:
        state.close()


def geo_resolver_loop(state_db: Path, endpoint: str, timeout: float, retry_seconds: int, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        resolved = resolve_one_location(state_db, endpoint, timeout, retry_seconds)
        stop_event.wait(1.2 if resolved else 10.0)


def record_sample(
    state: sqlite3.Connection,
    ports: dict[int, dict[str, object]],
    connections: list[Connection],
    now: int,
    retention_seconds: int,
) -> Counter[tuple[int, str]]:
    active = Counter(
        (item.local_port, item.remote_ip)
        for item in connections
        if item.local_port in ports
    )
    for (port, ip), count in active.items():
        state.execute(
            """
            INSERT INTO sightings(port, ip, first_seen, last_seen, samples)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(port, ip) DO UPDATE SET
                last_seen=excluded.last_seen,
                samples=sightings.samples + excluded.samples
            """,
            (port, ip, now, now, count),
        )
    state.execute("DELETE FROM sightings WHERE last_seen < ?", (now - retention_seconds,))
    state.commit()
    return active


def make_snapshot(
    state: sqlite3.Connection,
    ports: dict[int, dict[str, object]],
    active: Counter[tuple[int, str]],
    now: int,
) -> dict[str, object]:
    rows = state.execute(
        """
        SELECT sightings.port, sightings.ip, sightings.first_seen, sightings.last_seen, sightings.samples,
               COALESCE(geo_cache.location, '归属地查询中')
        FROM sightings
        LEFT JOIN geo_cache ON geo_cache.ip = sightings.ip
        ORDER BY sightings.port, sightings.last_seen DESC
        """
    ).fetchall()
    by_port: dict[int, list[dict[str, object]]] = {port: [] for port in ports}
    for port, ip, first_seen, last_seen, samples, location in rows:
        if port not in ports:
            continue
        by_port[port].append(
            {
                "ip": ip,
                "firstSeen": datetime.fromtimestamp(first_seen, timezone.utc).isoformat(),
                "lastSeen": datetime.fromtimestamp(last_seen, timezone.utc).isoformat(),
                "online": active[(port, ip)] > 0,
                "connections": active[(port, ip)],
                "samples": samples,
                "location": location,
            }
        )

    output_ports = []
    for port, metadata in sorted(ports.items()):
        ips = by_port[port]
        output_ports.append(
            {
                "port": port,
                **metadata,
                "activeIpCount": sum(1 for item in ips if item["online"]),
                "recent1h": sum(1 for item in ips if now - int(datetime.fromisoformat(str(item["lastSeen"])).timestamp()) <= 3600),
                "recent24h": sum(1 for item in ips if now - int(datetime.fromisoformat(str(item["lastSeen"])).timestamp()) <= 86400),
                "ips": ips,
            }
        )
    return {
        "schemaVersion": 1,
        "generatedAt": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "source": "proc-net-tcp",
        "ports": output_ports,
    }


def atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def start_http_server(output: Path, listen: str, port: int, token: str, allow_ip: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            remote_ip = self.client_address[0]
            authorization = self.headers.get("Authorization", "")
            supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
            if self.path != "/v1/snapshot" or remote_ip != allow_ip or not hmac.compare_digest(supplied, token):
                self.send_error(403)
                return
            try:
                body = output.read_bytes()
            except FileNotFoundError:
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer((listen, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="snapshot-http", daemon=True)
    thread.start()
    return server


def collect_once(args: argparse.Namespace, state: sqlite3.Connection, ports: dict[int, dict[str, object]]):
    now = int(time.time())
    connections = read_connections(args.proc_root)
    active = record_sample(state, ports, connections, now, args.retention_days * 86400)
    snapshot = make_snapshot(state, ports, active, now)
    atomic_write_json(args.output, snapshot)
    return snapshot


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xui-db", type=Path, default=Path("/etc/x-ui/x-ui.db"))
    parser.add_argument("--state-db", type=Path, default=Path("/var/lib/xui-connection-collector/state.db"))
    parser.add_argument("--output", type=Path, default=Path("/var/lib/xui-connection-collector/snapshot.json"))
    parser.add_argument("--proc-root", type=Path, default=Path("/proc/net"))
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--port-refresh", type=float, default=60.0)
    parser.add_argument("--retention-days", type=int, default=7)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=0)
    parser.add_argument("--allow-ip", default="127.0.0.1")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--geo-endpoint", default="https://ipwho.is/{ip}?lang=zh-CN")
    parser.add_argument("--geo-timeout", type=float, default=4.0)
    parser.add_argument("--geo-retry-hours", type=int, default=6)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--print", dest="print_snapshot", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state = open_state_db(args.state_db)
    server = None
    if args.http_port:
        if not args.token_file:
            raise SystemExit("--token-file is required with --http-port")
        token = args.token_file.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise SystemExit("collector token is too short")
        server = start_http_server(args.output, args.listen, args.http_port, token, args.allow_ip)
    stopping = False
    stop_event = threading.Event()
    geo_thread = threading.Thread(
        target=geo_resolver_loop,
        args=(args.state_db, args.geo_endpoint, args.geo_timeout, args.geo_retry_hours * 3600, stop_event),
        name="geo-resolver",
        daemon=True,
    )
    geo_thread.start()

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    ports: dict[int, dict[str, object]] = {}
    next_refresh = 0.0
    try:
        while not stopping:
            monotonic = time.monotonic()
            if monotonic >= next_refresh:
                ports = read_xui_ports(args.xui_db)
                next_refresh = monotonic + args.port_refresh
            snapshot = collect_once(args, state, ports)
            if args.print_snapshot:
                print(json.dumps(snapshot, ensure_ascii=False, indent=2))
            if args.once:
                break
            time.sleep(max(args.interval, 0.2))
    finally:
        stop_event.set()
        if server:
            server.shutdown()
        state.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
