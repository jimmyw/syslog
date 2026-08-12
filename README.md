# syslog-stack

Fast, efficient syslog collection → ClickHouse → React frontend, with MCP support.

## Architecture

```
Remote devices (UDP/TCP :514)
        │
        ▼
  syslog-receiver          Custom Go service
  (UDP+TCP :514)           Batched writes, ~2s flush
        │
        ▼
    ClickHouse              Columnar DB, LZ4+ZSTD
  (port 8123/9000)         Partitioned by month, 90d TTL
        │
        ▼
    frontend               nginx — serves SPA + proxies /ch, /poll, /mcp
        │
        ▼
  oauth2-proxy             GitHub OAuth — protects all HTTP endpoints
  (public :80)
        │
   ┌────┴────┐
   │         │
 browser  mcp-server       HTTP MCP server (Streamable HTTP transport)
           /mcp             5 tools, auth via _syslog session cookie
```

## Quick start

```bash
docker compose up -d --build
```

Frontend: http://localhost:8080
ClickHouse HTTP: http://localhost:8123 (local only)

## Configure devices

### Linux (rsyslog)

```
# /etc/rsyslog.d/99-remote.conf
*.* @<your-host-ip>:514          # UDP
# or
*.* @@<your-host-ip>:514         # TCP
```

```bash
systemctl restart rsyslog
```

### ESP32 / embedded

Use any syslog library targeting UDP port 514. RFC3164 and RFC5424 both supported.

Example log line (RFC3164):
```
<134>Jun  9 12:34:56 esp32-kitchen app[1]: Temperature: 23.4°C
```

### OpenWRT / syslog-ng

```
destination d_remote {
  syslog("<your-host-ip>" port(514) transport("udp"));
};
log { source(src); destination(d_remote); };
```

## CLI (`stream_host.py`)

A stdlib-only client for live tailing and bulk export. First run opens a browser
for GitHub OAuth and caches the session token (see [token expiry](#token-expiry)).

```bash
# Live stream (optionally filtered to host(s)/IP(s); multiple are ORed)
python stream_host.py                       # all hosts
python stream_host.py ec6260604234          # one host
python stream_host.py ec6260604234 --since 6h --tail 50
```

### Bulk export

Download a host + time window to a local file for offline analysis. The transfer
is gzip-compressed (ClickHouse `enable_http_compression`), so even large windows
move fast — a 6 h window of a chatty device (~370k rows, 84 MB) is ~3.5 MB on the
wire and lands in about a second.

```bash
# Human-readable text (same format as the live stream)
python stream_host.py ec6260604234 --since 6h --export logs.txt

# Raw JSON lines (one row per line, for jq/pandas)
python stream_host.py ec6260604234 --since 6h --export logs.jsonl --format jsonl

# Keep the file compressed on disk too (just give a .gz path)
python stream_host.py ec6260604234 --since 24h --export logs.jsonl.gz --format jsonl

# Bounded window with --until
python stream_host.py ec6260604234 --since 2d --until 1d --export window.jsonl --format jsonl
```

Flags: `--since` / `--until` (relative `5m,6h,2d` or ISO8601), `--format text|jsonl`,
`--limit N`, `--no-compress`. Output is gzipped automatically when the path ends in `.gz`.

> The MCP `query_logs` tool is capped at 1000 rows and is meant for interactive
> querying; use this CLI export for full windows / local file analysis.

## MCP Server

The MCP server runs as an HTTP service behind oauth2-proxy, reachable at `/mcp` on the same domain as the frontend. Authentication uses the same GitHub OAuth session cookie as the browser.

### 0. Get access

oauth2-proxy authorizes against an explicit username allowlist
(`GITHUB_ALLOWED_USERS` in the server's `.env`, wired to `--github-user`), not org
membership. A new user's GitHub username must be added there and oauth2-proxy
restarted, otherwise the login in step 1 just bounces back to GitHub.

Each user authenticates as themselves — session cookies are personal and must not
be shared or copied between machines.

### 1. Get a session token

Run `stream_host.py` once to authenticate and save a token:

```bash
python stream_host.py --logout  # clear any stale token
python stream_host.py           # opens browser, saves token, then Ctrl+C
```

The token is stored at `~/.config/syslog-stream/token-<hash>`. Read it:

```bash
cat ~/.config/syslog-stream/token-*
```

### 2. Configure Claude Code

Easiest is to let the CLI write the config, which registers the server for all
projects (user scope):

```bash
tok=$(cat ~/.config/syslog-stream/token-*)
claude mcp add-json syslog "{\"type\":\"http\",\"url\":\"https://syslog.wennlund.nu/mcp\",\"headers\":{\"Cookie\":\"_syslog=$tok\"}}" --scope user
```

To configure a single project instead, create `.mcp.json` at the project root:

```json
{
  "mcpServers": {
    "syslog": {
      "type": "http",
      "url": "https://syslog.wennlund.nu/mcp",
      "headers": {
        "Cookie": "_syslog=<paste token here>"
      }
    }
  }
}
```

> **Do not use `~/.claude/mcp.json`** — Claude Code does not read that path, and a
> config placed there silently never loads. The only locations that work are
> `.mcp.json` at a project root and the `mcpServers` block in `~/.claude.json`
> (which is what `claude mcp add-json --scope user` writes).

MCP servers are loaded at session start, so **restart Claude Code** after adding the
config. Verify with `claude mcp list`, or check that the `mcp__syslog__*` tools are
available in a new session.

### 3. Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "syslog": {
      "type": "http",
      "url": "https://syslog.wennlund.nu/mcp",
      "headers": {
        "Cookie": "_syslog=<paste token here>"
      }
    }
  }
}
```

### Token expiry

The `_syslog` session cookie expires after 90 days. Expiry is enforced server-side
via `max_age`, and a stale cookie shows up only as a `302` redirect to the GitHub
login — not as a clean error from the MCP tools.

The cookie is `<data>|<signed-at-unix-ts>|<signature>`. The middle number is the
time the cookie was **issued**, not when it expires — don't try to read an expiry
date out of it.

To refresh, mint a new token and re-register it. The token cached under
`~/.config/syslog-stream/` and the copy in the MCP config are independent, so
updating the cache alone is not enough:

```bash
python stream_host.py --logout
python stream_host.py            # browser login, then Ctrl+C
tok=$(cat ~/.config/syslog-stream/token-*)
claude mcp remove syslog --scope user
claude mcp add-json syslog "{\"type\":\"http\",\"url\":\"https://syslog.wennlund.nu/mcp\",\"headers\":{\"Cookie\":\"_syslog=$tok\"}}" --scope user
```

Restart Claude Code afterwards.

### Available tools

| Tool | Description |
|------|-------------|
| `query_logs` | Flexible log query with filters (host, app, severity, message, time range) |
| `get_stats` | Aggregated counts by host / severity / app / hour |
| `list_hosts` | All known hosts with last-seen and total count |
| `get_log_rate` | Time-series ingestion rate (minute/hour/day buckets) |
| `search_errors` | Recent errors/critical/alerts across all hosts |

### Example prompts

- *"Show me all errors from the ec6260604234 host in the last hour"*
- *"Which host is generating the most logs today?"*
- *"Show me the log rate for the last 24 hours"*
- *"Are there any critical or emergency logs in the past 30 minutes?"*

## ClickHouse schema

```sql
-- Main table: partitioned by month, ordered by (hostname, app_name, received_at)
-- TTL: 90 days (configurable in clickhouse/init.sql)
-- Compression: LZ4 for timestamps, ZSTD(3) for messages

-- Materialized view: host_stats_mv_target
-- Pre-aggregated hourly counts per host+severity for fast dashboard queries
```

## Performance

- Go receiver: single binary, handles ~50k msgs/sec on a modest VM
- Batch writes: 1000 rows or 2s, whichever comes first
- ClickHouse: columnar storage, LZ4/ZSTD compression, MergeTree engine
- Frontend: direct ClickHouse HTTP queries, no intermediate API layer

## Tuning

**Batch size / flush interval** (syslog-receiver/main.go):
```go
bw := NewBatchWriter(conn, 1000, 2*time.Second)  // 1000 rows or 2s
```

**TTL** (clickhouse/init.sql):
```sql
TTL toDateTime(received_at) + INTERVAL 90 DAY
```

**ClickHouse memory** — add to docker-compose.yml under clickhouse:
```yaml
environment:
  CLICKHOUSE_MAX_SERVER_MEMORY_USAGE: 2000000000  # 2GB
```
