import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from xui_connection_collector import (
    Connection,
    atomic_write_json,
    decode_proc_address,
    make_snapshot,
    lookup_maxmind_location,
    normalize_isp,
    open_state_db,
    parse_proc_net_tcp,
    record_sample,
)


PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF0000F95B0F67:4D93 0000000000000000FFFF0000D8DED431:9BD4 01 00000000:00000000 02:0000004F 00000000 0 0 1
   1: 0000000000000000FFFF0000F95B0F67:4D93 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2
"""


class CollectorTests(unittest.TestCase):
    def test_normalizes_chinese_carriers(self):
        self.assertEqual(normalize_isp("CHINA UNICOM China169 Backbone", "4837"), "中国联通")

    def test_maxmind_does_not_invent_a_city(self):
        class Names:
            def __init__(self, name="", names=None):
                self.name = name
                self.names = names or {}

        class Subdivisions(list):
            @property
            def most_specific(self):
                return self[-1]

        response = type("Response", (), {
            "country": Names("China", {"zh-CN": "中国"}),
            "subdivisions": Subdivisions(),
            "city": Names(),
            "location": type("Location", (), {"accuracy_radius": 1000})(),
        })()
        reader = type("Reader", (), {"city": lambda self, _ip: response})()
        result = lookup_maxmind_location("116.129.132.177", reader)
        self.assertEqual(result["location"], "中国 · 位置不确定")
        self.assertEqual(result["accuracy_radius"], 1000)

    def test_decodes_ipv4_mapped_ipv6(self):
        self.assertEqual(decode_proc_address("0000000000000000FFFF0000D8DED431", True), "49.212.222.216")

    def test_parses_only_established_connections(self):
        self.assertEqual(parse_proc_net_tcp(PROC_TCP6, True), [Connection(19859, "49.212.222.216")])

    def test_records_and_builds_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = open_state_db(root / "state.db")
            ports = {19859: {"id": 7, "remark": "test", "protocol": "dokodemo-door"}}
            active = record_sample(state, ports, [Connection(19859, "49.212.222.216")], 1000, 604800)
            payload = make_snapshot(state, ports, active, 1000)
            self.assertEqual(payload["ports"][0]["activeIpCount"], 1)
            self.assertEqual(payload["ports"][0]["ips"][0]["connections"], 1)
            self.assertFalse(payload["ports"][0]["ips"][0]["scanner"])
            output = root / "snapshot.json"
            atomic_write_json(output, payload)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schemaVersion"], 1)
            state.close()

    def test_short_visits_to_multiple_ports_are_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            state = open_state_db(Path(directory) / "state.db")
            ports = {
                19859: {"id": 7, "remark": "a", "protocol": "dokodemo-door"},
                19860: {"id": 8, "remark": "b", "protocol": "dokodemo-door"},
            }
            record_sample(state, ports, [Connection(19859, "85.217.149.38")], 1000, 604800)
            active = record_sample(state, ports, [Connection(19860, "85.217.149.38")], 1030, 604800)
            payload = make_snapshot(state, ports, active, 1030)
            entries = [item for port in payload["ports"] for item in port["ips"]]
            self.assertTrue(all(item["scanner"] for item in entries))
            self.assertTrue(all(item["scannedPorts"] == 2 for item in entries))
            self.assertEqual(payload["ports"][1]["activeIpCount"], 0)
            state.close()


if __name__ == "__main__":
    unittest.main()
