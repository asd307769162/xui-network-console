#!/usr/bin/env python3
"""Low-overhead connection collector for X-UI dokodemo-door inbounds."""

import argparse
import collections
import hmac
import ipaddress
import json
import mmap
import os
import signal
import sqlite3
import sys
import time
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


TCP_ESTABLISHED = "01"


Connection = collections.namedtuple("Connection", ("local_port", "remote_ip"))


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class QQWryReader:
    """Read the legacy GBK-encoded QQWry.dat format used by the 4T panel."""

    def __init__(self, path: Path):
        self.file = path.open("rb")
        self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        if len(self.data) < 8:
            self.close()
            raise ValueError("QQWry database is too small")
        self.first_index = self._u32(0)
        self.last_index = self._u32(4)
        if self.first_index < 8 or self.last_index < self.first_index or self.last_index + 7 > len(self.data):
            self.close()
            raise ValueError("QQWry database index is invalid")
        self.record_count = ((self.last_index - self.first_index) // 7) + 1

    def close(self):
        data = getattr(self, "data", None)
        if data:
            data.close()
            self.data = None
        file = getattr(self, "file", None)
        if file:
            file.close()
            self.file = None

    def _u24(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 3], "little")

    def _u32(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 4], "little")

    def _cstring(self, offset: int) -> Tuple[bytes, int]:
        end = self.data.find(b"\0", offset)
        if end < 0:
            raise ValueError("QQWry string terminator is missing")
        return bytes(self.data[offset:end]), end + 1

    def _area(self, offset: int) -> bytes:
        mode = self.data[offset]
        if mode == 0:
            return b""
        if mode in (1, 2):
            pointer = self._u24(offset + 1)
            return self._cstring(pointer)[0] if pointer else b""
        return self._cstring(offset)[0]

    def _decode(self, value: bytes) -> str:
        try:
            return value.decode("utf-8").strip()
        except UnicodeDecodeError:
            return value.decode("gb18030", errors="replace").strip()

    def lookup(self, ip: str) -> Tuple[str, str]:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            raise ValueError("QQWry only supports IPv4")
        target = int(address)
        lower, upper = 0, self.record_count - 1
        record_offset = None
        while lower <= upper:
            middle = (lower + upper) // 2
            index_offset = self.first_index + middle * 7
            begin_ip = self._u32(index_offset)
            candidate = self._u24(index_offset + 4)
            end_ip = self._u32(candidate)
            if target < begin_ip:
                upper = middle - 1
            elif target > end_ip:
                lower = middle + 1
            else:
                record_offset = candidate
                break
        if record_offset is None:
            raise LookupError(f"IP not found in QQWry: {ip}")

        country_offset = record_offset + 4
        mode = self.data[country_offset]
        if mode == 1:
            redirect = self._u24(country_offset + 1)
            redirect_mode = self.data[redirect]
            if redirect_mode == 2:
                country = self._cstring(self._u24(redirect + 1))[0]
                area = self._area(redirect + 4)
            else:
                country, area_offset = self._cstring(redirect)
                area = self._area(area_offset)
        elif mode == 2:
            country = self._cstring(self._u24(country_offset + 1))[0]
            area = self._area(country_offset + 4)
        else:
            country, area_offset = self._cstring(country_offset)
            area = self._area(area_offset)
        return self._decode(country), self._decode(area)


def decode_proc_address(value: str, ipv6: bool) -> str:
    raw = bytes.fromhex(value)
    if ipv6:
        raw = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
        address = ipaddress.IPv6Address(raw)
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    return str(ipaddress.IPv4Address(raw[::-1]))


def parse_proc_net_tcp(text: str, ipv6: bool = False) -> List[Connection]:
    connections = []  # type: List[Connection]
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


def read_connections(proc_root: Path) -> List[Connection]:
    result = []  # type: List[Connection]
    for name, ipv6 in (("tcp", False), ("tcp6", True)):
        path = proc_root / name
        try:
            result.extend(parse_proc_net_tcp(path.read_text(encoding="ascii"), ipv6))
        except FileNotFoundError:
            pass
    return result


def read_xui_ports(db_path: Path) -> Dict[int, Dict[str, object]]:
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
    connection = sqlite3.connect(str(path))
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


def normalize_isp(isp: str, asn: str = "") -> str:
    asn = asn.upper()
    asn = asn[2:] if asn.startswith("AS") else asn
    isp_key = isp.lower()
    if asn in {"9808", "56046", "24400"} or "china mobile" in isp_key:
        return "中国移动"
    if asn in {"4134", "4812", "4809"} or "china telecom" in isp_key:
        return "中国电信"
    if asn in {"4837", "9929", "17621"} or "china unicom" in isp_key:
        return "中国联通"
    return isp


def lookup_ip_location(ip: str, endpoint: str, timeout: float) -> Dict[str, object]:
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
    asn = str(connection.get("asn") or "")
    isp = normalize_isp(isp, asn)
    location = " · ".join(part for part in (country, region, city, isp) if part) or "未知"
    return {"location": location, "country": country, "region": region, "city": city, "isp": isp, "accuracy_radius": None}


def open_maxmind_readers(city_db: Optional[Path], asn_db: Optional[Path]):
    if not city_db:
        return None, None
    if not city_db.is_file():
        raise FileNotFoundError(f"MaxMind City database not found: {city_db}")
    try:
        import geoip2.database
    except ImportError as error:
        raise RuntimeError("python3-geoip2 is required for MaxMind lookup") from error
    city_reader = geoip2.database.Reader(str(city_db))
    asn_reader = geoip2.database.Reader(str(asn_db)) if asn_db and asn_db.is_file() else None
    return city_reader, asn_reader


def lookup_maxmind_location(ip: str, city_reader, asn_reader=None) -> Dict[str, object]:
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {"location": "内网地址", "country": "", "region": "", "city": "", "isp": "", "accuracy_radius": None}
    response = city_reader.city(ip)
    country = str(response.country.names.get("zh-CN") or response.country.name or "")
    region = ""
    if response.subdivisions:
        region = str(response.subdivisions.most_specific.names.get("zh-CN") or response.subdivisions.most_specific.name or "")
    city = str(response.city.names.get("zh-CN") or response.city.name or "")
    radius = response.location.accuracy_radius
    isp = ""
    if asn_reader:
        try:
            asn_response = asn_reader.asn(ip)
            isp = normalize_isp(str(asn_response.autonomous_system_organization or ""), str(asn_response.autonomous_system_number or ""))
        except Exception:
            pass
    geo_parts = [part for part in (country, region, city) if part]
    if not region and not city:
        geo_parts.append("位置不确定")
    location = " · ".join(geo_parts + ([isp] if isp else [])) or "未知"
    return {"location": location, "country": country, "region": region, "city": city, "isp": isp, "accuracy_radius": radius}


def lookup_qqwry_china(ip: str, reader: QQWryReader) -> Optional[Dict[str, object]]:
    if ipaddress.ip_address(ip).version != 4:
        return None
    country_text, area_text = reader.lookup(ip)
    normalized = country_text.replace("—", "–").replace("-", "–")
    parts = [part.strip() for part in normalized.split("–") if part.strip()]
    if not parts or parts[0] != "中国":
        return None
    if area_text.upper() == "CZ88.NET":
        area_text = ""
    country = parts[0]
    region = parts[1] if len(parts) > 1 else ""
    city = parts[2] if len(parts) > 2 else ""
    location_parts = list(parts)
    if area_text and area_text not in location_parts:
        location_parts.append(area_text)
    return {
        "location": " · ".join(location_parts),
        "country": country,
        "region": region,
        "city": city,
        "isp": area_text,
        "accuracy_radius": None,
    }


def lookup_preferred_location(ip: str, endpoint: str, timeout: float, maxmind_readers: Tuple[object, object], qqwry_reader=None) -> Dict[str, object]:
    if qqwry_reader:
        try:
            qqwry_result = lookup_qqwry_china(ip, qqwry_reader)
            if qqwry_result:
                return qqwry_result
        except Exception as error:
            print(f"QQWry lookup failed for {ip}: {type(error).__name__}: {error}", file=sys.stderr, flush=True)
    city_reader, asn_reader = maxmind_readers
    return lookup_maxmind_location(ip, city_reader, asn_reader) if city_reader else lookup_ip_location(ip, endpoint, timeout)


def resolve_one_location(state_db: Path, endpoint: str, timeout: float, retry_seconds: int, maxmind_readers: Tuple[object, object] = (None, None), qqwry_reader=None) -> bool:
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
            result = lookup_preferred_location(ip, endpoint, timeout, maxmind_readers, qqwry_reader)
            values = (ip, result["location"], result["country"], result["region"], result["city"], result["isp"], "ok", now)
        except Exception as error:
            print(
                f"geolocation lookup failed for {ip}: {type(error).__name__}: {error}",
                file=sys.stderr,
                flush=True,
            )
            values = (ip, "归属地查询失败", "", "", "", "", "failed", now)
        state.execute(
            """
            INSERT OR REPLACE INTO geo_cache(
                ip, location, country, region, city, isp, status, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        state.commit()
        return True
    finally:
        state.close()


def geo_resolver_loop(state_db: Path, endpoint: str, timeout: float, retry_seconds: int, stop_event: threading.Event, city_db: Optional[Path] = None, asn_db: Optional[Path] = None, qqwry_db: Optional[Path] = None) -> None:
    readers = open_maxmind_readers(city_db, asn_db)
    qqwry_reader = QQWryReader(qqwry_db) if qqwry_db else None
    try:
        while not stop_event.is_set():
            resolved = resolve_one_location(state_db, endpoint, timeout, retry_seconds, readers, qqwry_reader)
            stop_event.wait(1.2 if resolved else 10.0)
    finally:
        if qqwry_reader:
            qqwry_reader.close()
        for reader in readers:
            if reader:
                reader.close()


def record_sample(
    state: sqlite3.Connection,
    ports: Dict[int, Dict[str, object]],
    connections: List[Connection],
    now: int,
    retention_seconds: int,
) -> Counter:
    active = Counter(
        (item.local_port, item.remote_ip)
        for item in connections
        if item.local_port in ports
    )
    for (port, ip), count in active.items():
        inserted = state.execute(
            """
            INSERT OR IGNORE INTO sightings(port, ip, first_seen, last_seen, samples)
            VALUES (?, ?, ?, ?, ?)
            """,
            (port, ip, now, now, count),
        )
        if inserted.rowcount == 0:
            state.execute(
                """
                UPDATE sightings
                SET last_seen = ?, samples = samples + ?
                WHERE port = ? AND ip = ?
                """,
                (now, count, port, ip),
            )
    state.execute("DELETE FROM sightings WHERE last_seen < ?", (now - retention_seconds,))
    state.commit()
    return active


def make_snapshot(
    state: sqlite3.Connection,
    ports: Dict[int, Dict[str, object]],
    active: Counter,
    now: int,
) -> Dict[str, object]:
    rows = state.execute(
        """
        SELECT sightings.port, sightings.ip, sightings.first_seen, sightings.last_seen, sightings.samples,
               COALESCE(geo_cache.location, '归属地查询中')
        FROM sightings
        LEFT JOIN geo_cache ON geo_cache.ip = sightings.ip
        ORDER BY sightings.port, sightings.last_seen DESC
        """
    ).fetchall()
    ip_port_durations = {}  # type: Dict[str, List[int]]
    for _port, ip, first_seen, last_seen, _samples, _location in rows:
        ip_port_durations.setdefault(str(ip), []).append(int(last_seen) - int(first_seen))
    scanner_ips = {
        ip for ip, durations in ip_port_durations.items()
        if len(durations) >= 2 and all(duration < 60 for duration in durations)
    }
    by_port = {port: [] for port in ports}  # type: Dict[int, List[Dict[str, object]]]
    for port, ip, first_seen, last_seen, samples, location in rows:
        if port not in ports:
            continue
        by_port[port].append(
            {
                "ip": ip,
                "firstSeen": datetime.fromtimestamp(first_seen, timezone.utc).isoformat(),
                "lastSeen": datetime.fromtimestamp(last_seen, timezone.utc).isoformat(),
                "_lastSeenEpoch": int(last_seen),
                "online": active[(port, ip)] > 0,
                "connections": active[(port, ip)],
                "samples": samples,
                "location": location,
                "scanner": ip in scanner_ips,
                "scannedPorts": len(ip_port_durations.get(str(ip), [])),
            }
        )

    output_ports = []
    for port, metadata in sorted(ports.items()):
        ips = by_port[port]
        user_ips = [item for item in ips if not item["scanner"]]
        recent1h = sum(1 for item in user_ips if now - int(item["_lastSeenEpoch"]) <= 3600)
        recent24h = sum(1 for item in user_ips if now - int(item["_lastSeenEpoch"]) <= 86400)
        for item in ips:
            item.pop("_lastSeenEpoch", None)
        output_ports.append(
            {
                "port": port,
                **metadata,
                "activeIpCount": sum(1 for item in user_ips if item["online"]),
                "recent1h": recent1h,
                "recent24h": recent24h,
                "ips": ips,
            }
        )
    return {
        "schemaVersion": 1,
        "generatedAt": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "source": "proc-net-tcp",
        "ports": output_ports,
    }


def atomic_write_json(path: Path, payload: Dict[str, object]) -> None:
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


def collect_once(args: argparse.Namespace, state: sqlite3.Connection, ports: Dict[int, Dict[str, object]]):
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
    parser.add_argument("--maxmind-city-db", type=Path)
    parser.add_argument("--maxmind-asn-db", type=Path)
    parser.add_argument("--qqwry-db", type=Path)
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
        args=(args.state_db, args.geo_endpoint, args.geo_timeout, args.geo_retry_hours * 3600, stop_event, args.maxmind_city_db, args.maxmind_asn_db, args.qqwry_db),
        name="geo-resolver",
        daemon=True,
    )
    geo_thread.start()

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    ports = {}  # type: Dict[int, Dict[str, object]]
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
