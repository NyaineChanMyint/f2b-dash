#!/usr/bin/env python3
"""Incrementally ship local Fail2Ban log events to Fail2Ban Dashboard Central."""
import argparse, json, os, re, socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

PATTERN = re.compile(r"^(?P<time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*?\[(?P<jail>[\w-]+)\]\s+(?:(?P<kind>Found|Ban|Unban|Restore Ban|Ignore)\s+(?P<ip>[0-9a-fA-F:.]+)|(?P<ip2>[0-9a-fA-F:.]+) already banned)")
KINDS = {"Restore Ban": "RestoreBan"}

def main():
    p = argparse.ArgumentParser(); p.add_argument("--url", required=True); p.add_argument("--token", required=True)
    p.add_argument("--log", default="/var/log/fail2ban.log"); p.add_argument("--state", default="/var/lib/f2b-dashboard-agent/state.json"); p.add_argument("--host", default=socket.getfqdn()); args = p.parse_args()
    state_file = Path(args.state); state_file.parent.mkdir(parents=True, exist_ok=True)
    try: state = json.loads(state_file.read_text())
    except (FileNotFoundError, json.JSONDecodeError): state = {}
    log = Path(args.log); stat = log.stat(); start = state.get("offset", 0) if state.get("inode") == stat.st_ino and stat.st_size >= state.get("offset", 0) else 0
    events = []
    with log.open("r", errors="replace") as f:
        f.seek(start)
        for line in f:
            m = PATTERN.match(line)
            if not m: continue
            local = datetime.strptime(m["time"], "%Y-%m-%d %H:%M:%S").astimezone()
            events.append({"timestamp": local.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), "kind": KINDS.get(m["kind"], m["kind"] or "AlreadyBanned"), "ip": m["ip"] or m["ip2"], "jail": m["jail"], "message": line.strip()[-500:]})
        offset = f.tell()
    data = json.dumps({"host": args.host, "agent_version": "1.0", "events": events}).encode()
    request = Request(args.url.rstrip("/") + "/api/v1/events", data=data, headers={"Content-Type": "application/json", "X-Api-Token": args.token}, method="POST")
    with urlopen(request, timeout=20) as response:
        if response.status not in (200, 201): raise RuntimeError("server rejected events")
    state_file.write_text(json.dumps({"inode": stat.st_ino, "offset": offset}))

if __name__ == "__main__": main()
