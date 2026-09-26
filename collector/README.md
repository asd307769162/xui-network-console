# X-UI connection collector

This collector observes TCP connection metadata from `/proc/net/tcp*`, maps local ports to enabled X-UI inbounds, and retains seven days of first/last-seen IP metadata in a local SQLite database.

It does not capture packet contents, open a network listener, alter firewall rules, or enable/disable X-UI inbounds. The initial pilot writes only:

- `/var/lib/xui-connection-collector/state.db`
- `/var/lib/xui-connection-collector/snapshot.json`

Run the tests:

```bash
cd collector
python3 -m unittest -v
```

Run one read-only sample:

```bash
python3 xui_connection_collector.py --once --print
```

The production collector samples established TCP sessions every five seconds. UDP is intentionally not collected. Its authenticated snapshot endpoint must be restricted to the central console IP.

IP geolocation is resolved asynchronously and cached in SQLite. Production uses the same free legacy `QQWry.dat` source as the 4T panel for mainland-China IPv4 addresses, then falls back to local MaxMind GeoLite2 City for overseas and IPv6 addresses. GeoLite2 ASN remains available for network ownership outside QQWry results. If MaxMind has no province or city, the collector displays `位置不确定` instead of replacing it with a lower-confidence online guess. The legacy IPWho endpoint remains available only when no local database is configured. Failed lookups wait six hours before retrying.

The MaxMind account ID and license key belong only in `/etc/xui-geoip.conf` with mode `0600`. `update-xui-geoip` always updates the public QQWry database atomically and additionally updates City and ASN when that MaxMind configuration exists. The accompanying systemd timer refreshes the available databases weekly. Never commit the MaxMind configuration or its values. QQWry data is downloaded from the public `nmgliangwei/qqwry` GitHub mirror and is not committed to this repository.

An IP is classified as a scanner only when it has reached at least two monitored ports and its observed duration on every reached port is under 60 seconds. Scanner records remain visible but are excluded from concurrent-user and sharing-risk counts.
