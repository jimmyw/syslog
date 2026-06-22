#!/usr/bin/env python3
"""Stream syslog entries, optionally filtered to a specific host.

Usage:
  python stream_host.py                     # stream all hosts
  python stream_host.py myserver            # filter to one host
  python stream_host.py myserver --since 6h --tail 50
  python stream_host.py --url https://syslog.wennlund.nu/
  python stream_host.py --logout            # clear stored session

Export a time window to a local file (gzip-compressed transfer):
  python stream_host.py myserver --since 6h --export logs.txt
  python stream_host.py myserver --since 2d --until 1d --export win.jsonl --format jsonl
  python stream_host.py myserver --since 24h --export logs.jsonl.gz --format jsonl
"""

import argparse
import base64
import gzip
import http.server
import io
import json
import os
import pathlib
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser

DEFAULT_URL = "https://syslog.wennlund.nu"
TOKEN_DIR   = pathlib.Path.home() / ".config" / "syslog-stream"

SEVERITY_COLORS = {
    "emerg":   "\033[1;35m",
    "alert":   "\033[1;31m",
    "crit":    "\033[1;31m",
    "err":     "\033[31m",
    "error":   "\033[31m",
    "warning": "\033[33m",
    "notice":  "\033[36m",
    "info":    "\033[1m",
    "debug":   "\033[2m",
}
SEVERITY_SHORT = {
    "emerg":   "emrg",
    "alert":   "alrt",
    "crit":    "crit",
    "err":     "erro",
    "error":   "erro",
    "warning": "warn",
    "notice":  "noti",
    "info":    "info",
    "debug":   "debu",
}
RESET = "\033[0m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
CYAN  = "\033[36m"


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _token_file(base_url):
    import hashlib
    slug = hashlib.md5(base_url.encode()).hexdigest()[:12]
    return TOKEN_DIR / f"token-{slug}"


def load_token(base_url):
    f = _token_file(base_url)
    return f.read_text().strip() if f.exists() else None


def save_token(base_url, token):
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    f = _token_file(base_url)
    f.write_text(token)
    f.chmod(0o600)


def delete_token(base_url):
    _token_file(base_url).unlink(missing_ok=True)


def validate_token(base_url, token):
    try:
        req = urllib.request.Request(
            f"{base_url}/oauth2/userinfo",
            headers={"Cookie": f"_syslog={token}"},
        )
        # Use a no-redirect opener so a 302 → login is detected as invalid
        class _NoRedirect(urllib.request.HTTPErrorProcessor):
            def http_response(self, request, response):
                return response
            https_response = http_response

        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def _free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def browser_login(base_url):
    """Open browser for GitHub OAuth, return the captured session cookie value."""
    port      = _free_port()
    captured  = []
    done      = threading.Event()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/done":
                params = dict(urllib.parse.parse_qsl(parsed.query))
                token  = params.get("token", "")
                captured.append(token)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h2>Logged in. You can close this tab.</h2>")
                done.set()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass  # silence request log

    server = http.server.HTTPServer(("localhost", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    cb  = urllib.parse.quote(f"http://localhost:{port}/done", safe=":/")
    url = f"{base_url}/api/cli-token?cb={cb}"
    print("Opening browser for GitHub login…", flush=True)
    webbrowser.open(url)

    if not done.wait(timeout=120):
        server.shutdown()
        raise TimeoutError("Login timed out after 2 minutes")

    server.shutdown()
    return captured[0]


def ensure_auth(base_url):
    token = load_token(base_url)
    if token and validate_token(base_url, token):
        return token
    if token:
        print("Session expired, logging in again…", flush=True)
    token = browser_login(base_url)
    save_token(base_url, token)
    print("Session saved.", flush=True)
    return token


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _opener(token):
    """urllib opener that attaches the session cookie to every request."""
    class _CookieHandler(urllib.request.BaseHandler):
        def http_request(self, req):
            req.add_header("Cookie", f"_syslog={token}")
            return req
        https_request = http_request

    return urllib.request.build_opener(_CookieHandler)


def relative_to_sql(rel):
    m = re.match(r"^(\d+)([mhd])$", rel)
    if not m:
        return f"'{rel}'"
    unit_map = {"m": "MINUTE", "h": "HOUR", "d": "DAY"}
    return f"now() - INTERVAL {m.group(1)} {unit_map[m.group(2)]}"


def ch_query(base_url, sql, opener):
    params = urllib.parse.urlencode({
        "query": sql,
        "default_format": "JSONEachRow",
        "database": "syslog",
    })
    url = f"{base_url}/ch/?{params}"
    with opener.open(url, timeout=30) as resp:
        text = resp.read().decode()
    return [json.loads(line) for line in text.strip().split("\n") if line]


def host_where_sql(hosts):
    """Build a WHERE clause matching any of `hosts` (ORed), or '' for no filter."""
    if not hosts:
        return ""
    clauses = " OR ".join(
        "(lower(hostname) LIKE lower('{h}%') OR source_ip = '{h}' "
        "OR lower(app_name) = lower('{h}') OR lower(app_name) LIKE lower('{h} %'))".format(
            h=h.replace("'", "''"))
        for h in hosts
    )
    return f"({clauses})"


def ch_query_stream(base_url, sql, opener, compress=True):
    """Yield result lines from /ch one at a time, with optional gzip transfer.

    ClickHouse gzips the response body when enable_http_compression=1 and the
    request advertises Accept-Encoding: gzip — this slashes transfer size for
    large exports. We stream + decompress incrementally so memory stays flat
    regardless of result size.
    """
    params = {
        "query": sql,
        "default_format": "JSONEachRow",
        "database": "syslog",
    }
    if compress:
        params["enable_http_compression"] = "1"
    url = f"{base_url}/ch/?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    if compress:
        req.add_header("Accept-Encoding", "gzip")
    resp = opener.open(req, timeout=300)
    stream = resp
    if resp.headers.get("Content-Encoding", "").lower() == "gzip":
        stream = gzip.GzipFile(fileobj=resp)
    reader = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
    for line in reader:
        line = line.rstrip("\n")
        if line:
            yield line


def export_logs(base_url, opener, hosts, since, until, fmt, limit, out_path, compress):
    """Stream a host/time-window query to a local file. Returns (rows, bytes, secs)."""
    sql = (
        "SELECT received_at, hostname, app_name, proc_id, severity_name, source_ip, message "
        "FROM syslog.logs "
        f"WHERE received_at >= {relative_to_sql(since)}"
    )
    if until:
        sql += f" AND received_at <= {relative_to_sql(until)}"
    host_where = host_where_sql(hosts)
    if host_where:
        sql += f" AND {host_where}"
    sql += " ORDER BY received_at ASC"
    if limit:
        sql += f" LIMIT {int(limit)}"

    open_out = gzip.open if out_path.endswith(".gz") else open
    rows = 0
    t0 = time.time()
    with open_out(out_path, "wt", encoding="utf-8") as fh:
        for line in ch_query_stream(base_url, sql, opener, compress=compress):
            if fmt == "jsonl":
                fh.write(line + "\n")
            else:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fh.write(format_log(row, color=False) + "\n")
            rows += 1
    return rows, os.path.getsize(out_path), time.time() - t0



# ── WebSocket client (stdlib only) ───────────────────────────────────────────

def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("WebSocket connection closed")
        buf += chunk
    return buf


def _ws_connect(base_url, path, token):
    parsed = urllib.parse.urlparse(base_url)
    use_ssl = parsed.scheme in ("https", "wss")
    host = parsed.hostname
    port = parsed.port or (443 if use_ssl else 80)

    raw = socket.create_connection((host, port), timeout=15)
    if use_ssl:
        ctx = ssl.create_default_context()
        raw = ctx.wrap_socket(raw, server_hostname=host)

    key = base64.b64encode(os.urandom(16)).decode()
    raw.sendall((
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Cookie: _syslog={token}\r\n"
        f"\r\n"
    ).encode())

    response = b""
    while b"\r\n\r\n" not in response:
        response += raw.recv(4096)
    status = response.split(b"\r\n")[0].decode()
    if "101" not in status:
        raise ConnectionError(f"WebSocket upgrade failed: {status}")
    return raw


def _ws_read_frame(sock):
    """Return (opcode, payload) for one frame."""
    header = _recv_exactly(sock, 2)
    opcode = header[0] & 0x0F
    masked = (header[1] & 0x80) != 0
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exactly(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exactly(sock, 8))[0]
    mask = _recv_exactly(sock, 4) if masked else None
    payload = _recv_exactly(sock, length)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def _ws_send_frame(sock, opcode, payload=b""):
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    header = bytes([0x80 | opcode, 0x80 | len(payload)]) + mask
    sock.sendall(header + masked)


def _ws_path(hosts):
    """Build /ws path with server-side filter params.

    Single host: sent as hostname= or source_ip= so the server pre-filters.
    Multiple hosts: no server param (OR logic unsupported); client filters instead.
    """
    if len(hosts) != 1:
        return "/ws"
    h = hosts[0]
    # Bare IPv4 address → filter by source_ip (exact); otherwise hostname (substring).
    try:
        socket.inet_aton(h)
        key = "source_ip"
    except OSError:
        key = "hostname"
    return f"/ws?{urllib.parse.urlencode({key: h})}"


def ws_stream(base_url, token, hosts, color):
    """Connect to /ws and print matching log entries until KeyboardInterrupt."""
    path = _ws_path(hosts)
    # For multiple hosts the server sends everything; client applies host_matches.
    client_filter = len(hosts) > 1

    while True:
        try:
            sock = _ws_connect(base_url, path, token)
            while True:
                opcode, payload = _ws_read_frame(sock)
                if opcode == 0x8:   # close
                    break
                if opcode == 0x9:   # ping → pong
                    _ws_send_frame(sock, 0xA, payload)
                    continue
                if opcode == 0x1:   # text frame
                    log = json.loads(payload.decode())
                    if client_filter and not any(host_matches(log, h) for h in hosts):
                        continue
                    print(format_log(log, color), flush=True)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"WebSocket error (retrying in 3s): {e}", file=sys.stderr)
            time.sleep(3)


# ── Formatting ────────────────────────────────────────────────────────────────

HOST_W = 26  # "B8T5-B833 (176.10.148.72)" = 25
APP_W  = 26  # "ota_coordinator[ota_task]" = 25
SEV_W  = 6   # "[xxxx]" = 6, all shorts are exactly 4 chars


def format_log(log, color=True):
    ts       = log.get("received_at", "")[:19]
    src      = log.get("source_ip", "")
    hn       = log.get("hostname", "")
    hostname = hn or src or "?"
    ip_tag   = f" ({src})" if src and src != hostname else ""
    app      = log.get("app_name", "-")
    pid      = log.get("proc_id", "")
    sev      = log.get("severity_name", "info").lower()
    msg      = log.get("message", "")
    proc     = f"[{pid}]" if pid and pid not in ("-", "") else ""
    sev_str  = f"[{SEVERITY_SHORT.get(sev, sev[:4])}]"

    if color:
        c    = SEVERITY_COLORS.get(sev, "")
        msg_c = DIM if sev == "debug" else (BOLD if sev == "info" else "")
        host_pad = " " * max(0, HOST_W - len(hostname) - len(ip_tag))
        app_pad  = " " * max(0, APP_W  - len(app) - len(proc))
        sev_pad  = " " * max(0, SEV_W  - len(sev_str))
        return (
            f"{DIM}{ts}{RESET}  "
            f"{BOLD}{hostname}{RESET}{DIM}{ip_tag}{RESET}{host_pad}  "
            f"{CYAN}{app}{proc}{RESET}{app_pad}  "
            f"{c}{sev_str}{RESET}{sev_pad} "
            f"{msg_c}{msg}{RESET}"
        )
    host_col = (hostname + ip_tag).ljust(HOST_W)
    app_col  = (app + proc).ljust(APP_W)
    sev_col  = sev_str.ljust(SEV_W)
    return f"{ts}  {host_col}  {app_col}  {sev_col} {msg}"


def host_matches(log, host):
    hn = log.get("hostname", "").lower()
    ip = log.get("source_ip", "")
    ap = log.get("app_name", "").lower()
    h  = host.lower()
    return (hn == h or hn.startswith(h + ".") or hn.startswith(h)
            or ip == host
            or ap == h or ap.startswith(h + " "))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Stream syslog entries from the syslog frontend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("host", nargs="*", default=None,
                        help="Hostname(s) or IP(s) to filter on — multiple values are ORed (omit to stream all hosts)")
    parser.add_argument("--url", default=DEFAULT_URL, metavar="URL",
                        help=f"Frontend base URL (default: {DEFAULT_URL})")
    parser.add_argument("--tail", type=int, default=20, metavar="N",
                        help="Historical lines before live streaming (default: 20, 0 to skip)")
    parser.add_argument("--since", default="1h",
                        help="Time window start: 5m, 15m, 1h, 6h, 24h, 7d or ISO8601 (default: 1h)")
    parser.add_argument("--until", default=None,
                        help="Time window end for --export: relative (30m, 2h) or ISO8601 (default: now)")
    parser.add_argument("--export", "-o", dest="export", metavar="PATH", default=None,
                        help="Export the matching window to PATH instead of live streaming. "
                             "Transfer is gzip-compressed; use a .gz path to keep the file compressed too.")
    parser.add_argument("--format", dest="fmt", choices=("text", "jsonl"), default="text",
                        help="Export format: text (human-readable, default) or jsonl (raw JSON rows)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max rows to export (default: unlimited)")
    parser.add_argument("--no-compress", action="store_true",
                        help="Disable gzip HTTP compression during --export")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--logout", action="store_true",
                        help="Delete stored session and exit")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    hosts    = args.host or []
    color    = not args.no_color and sys.stdout.isatty()

    if args.logout:
        delete_token(base_url)
        print("Session deleted.")
        return

    token  = ensure_auth(base_url)
    opener = _opener(token)

    # --- Bulk export to file (no live stream) ---
    if args.export:
        target = " or ".join(hosts) if hosts else "all hosts"
        window = f"since {args.since}" + (f" until {args.until}" if args.until else "")
        print(f"Exporting {target} ({window}) → {args.export} …", file=sys.stderr, flush=True)
        try:
            rows, size, dt = export_logs(
                base_url, opener, hosts, args.since, args.until,
                args.fmt, args.limit, args.export, not args.no_compress,
            )
        except Exception as e:
            print(f"Export failed: {e}", file=sys.stderr)
            sys.exit(1)
        mb = size / (1024 * 1024)
        rate = (mb / dt) if dt > 0 else 0
        print(f"Wrote {rows} rows, {mb:.1f} MB in {dt:.1f}s ({rate:.1f} MB/s on disk)",
              file=sys.stderr)
        return

    # --- Historical tail ---
    if args.tail > 0:
        since_expr = relative_to_sql(args.since)
        sql = (
            "SELECT received_at, hostname, app_name, proc_id, severity_name, source_ip, message "
            "FROM syslog.logs "
            f"WHERE received_at >= {since_expr}"
        )
        host_where = host_where_sql(hosts)
        if host_where:
            sql += f" AND {host_where}"
        sql += f" ORDER BY received_at DESC LIMIT {args.tail}"

        try:
            rows = ch_query(base_url, sql, opener)
            rows.reverse()
            if rows:
                sep = f"{DIM}--- last {len(rows)} lines ({args.since}) ---{RESET}" if color else f"--- last {len(rows)} lines ({args.since}) ---"
                print(sep, flush=True)
                for row in rows:
                    print(format_log(row, color), flush=True)
                live_sep = f"{DIM}--- live ---{RESET}" if color else "--- live ---"
                print(live_sep, flush=True)
            else:
                target = " or ".join(f"'{h}'" for h in hosts) if hosts else "any host"
                print(f"(no logs found for {target} in the last {args.since})", flush=True)
        except Exception as e:
            print(f"Warning: could not fetch historical logs: {e}", file=sys.stderr)

    # --- Live WebSocket stream ---
    hint = f"Streaming {' | '.join(hosts)} — Ctrl+C to stop" if hosts else "Streaming all hosts — Ctrl+C to stop"
    print(f"{DIM}{hint}{RESET}" if color else hint, flush=True)

    try:
        ws_stream(base_url, token, hosts, color)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
