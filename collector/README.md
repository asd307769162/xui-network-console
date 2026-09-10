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

The first pilot covers established TCP sessions. UDP history and central-console delivery are intentionally deferred until the TCP mapping is verified on one server.
