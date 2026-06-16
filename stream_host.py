#!/usr/bin/env python3
"""Stream syslog entries, optionally filtered to a specific host.

Usage:
  python stream_host.py                     # stream all hosts
  python stream_host.py myserver            # filter to one host
  python stream_host.py myserver --since 6h --tail 50
  python stream_host.py --url https://syslog.wennlund.nu/
  python stream_host.py --logout            # clear stored session
"""

import argparse
import base64
import http.server
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
    "info":    "\033[0m",
    "debug":   "\033[2m",
}
RESET = "\033[0m"
DIM   = "\033[2m"
BOLD  = "\033[1m"


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


def ws_stream(base_url, token, hosts, color):
    """Connect to /ws and print matching log entries until KeyboardInterrupt."""
    while True:
        try:
            sock = _ws_connect(base_url, "/ws", token)
            while True:
                opcode, payload = _ws_read_frame(sock)
                if opcode == 0x8:   # close
                    break
                if opcode == 0x9:   # ping → pong
                    _ws_send_frame(sock, 0xA, payload)
                    continue
                if opcode == 0x1:   # text frame
                    log = json.loads(payload.decode())
                    if not hosts or any(host_matches(log, h) for h in hosts):
                        print(format_log(log, color), flush=True)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"WebSocket error (retrying in 3s): {e}", file=sys.stderr)
            time.sleep(3)


# ── Formatting ────────────────────────────────────────────────────────────────

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

    if color:
        c = SEVERITY_COLORS.get(sev, "")
        return f"{DIM}{ts}{RESET}  {BOLD}{hostname}{RESET}{DIM}{ip_tag}{RESET}  {app}{proc}  {c}[{sev}]  {msg}{RESET}"
    return f"{ts}  {hostname}{ip_tag}  {app}{proc}  [{sev}]  {msg}"


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
                        help="Time window for historical tail: 5m, 15m, 1h, 6h, 24h, 7d (default: 1h)")
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

    # --- Historical tail ---
    if args.tail > 0:
        since_expr = relative_to_sql(args.since)
        sql = (
            "SELECT received_at, hostname, app_name, proc_id, severity_name, source_ip, message "
            "FROM syslog.logs "
            f"WHERE received_at >= {since_expr}"
        )
        if hosts:
            clauses = " OR ".join(
                "(lower(hostname) LIKE lower('{h}%') OR source_ip = '{h}' OR lower(app_name) = lower('{h}') OR lower(app_name) LIKE lower('{h} %'))".format(h=h.replace("'", "''"))
                for h in hosts
            )
            sql += f" AND ({clauses})"
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
