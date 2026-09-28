# syslog-stack

Fast, efficient syslog collection → ClickHouse → React frontend, with MCP support.

## Architecture

```
Remote devices (UDP/TCP :514)
        │
        ▼
  syslog-receiver          Rust / io_uring (monoio), thread-per-core
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
           /mcp             5 tools, OAuth bearer tokens
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

The MCP server is its own OAuth 2.1 authorization server (GitHub is the identity
provider), reachable at `/mcp` on the same domain as the frontend. MCP clients
authenticate with `claude mcp login` / the client's built-in login — no tokens to
copy around. oauth2-proxy still protects the web UI; `/mcp` and the OAuth
endpoints (`/.well-known/*`, `/register`, `/authorize`, `/token`) bypass it and
are handled by `mcp-server` itself.

### 0. Server setup (once)

Classic GitHub OAuth Apps allow only one callback URL and the first is used by
oauth2-proxy, so create a **second** OAuth App for MCP:

- Callback URL: `https://syslog.wennlund.nu/mcp/oauth/github/callback`
- Put its credentials in `.env` as `MCP_GITHUB_CLIENT_ID` / `MCP_GITHUB_CLIENT_SECRET`

Then `docker compose up -d --build mcp-server oauth2-proxy frontend`.

### 1. Get access

Authorization is an explicit username allowlist (`GITHUB_ALLOWED_USERS` in the
server's `.env`, shared by oauth2-proxy and the MCP server), not org membership.
A new user's GitHub username must be added there and `mcp-server` +
`oauth2-proxy` restarted, otherwise login ends on an "Access denied" page.

### 2. Configure Claude Code

```bash
claude mcp add --transport http syslog https://syslog.wennlund.nu/mcp --scope user
claude mcp login syslog
```

`login` opens a browser for GitHub. Access tokens last 1 hour and are refreshed
automatically with a rotating refresh token (valid 1 year), so you normally log in
once per machine. To configure a single project instead, put this in `.mcp.json`
and run `claude mcp login syslog`:

```json
{
  "mcpServers": {
    "syslog": { "type": "http", "url": "https://syslog.wennlund.nu/mcp" }
  }
}
```

> **Do not use `~/.claude/mcp.json`** — Claude Code does not read that path. The
> only locations that work are `.mcp.json` at a project root and the `mcpServers`
> block in `~/.claude.json` (what `claude mcp add --scope user` writes).

Restart Claude Code after adding the config, then check `claude mcp list`.

### 3. Configure Claude Desktop

Add the server as a custom connector with URL `https://syslog.wennlund.nu/mcp`
and complete the GitHub login when prompted.

### Revoking access

Issued clients and tokens live in the `mcp_oauth_data` volume
(`/data/oauth-store.json`). Remove a user from `GITHUB_ALLOWED_USERS` and restart
`mcp-server` to cut them off (checked on every request), or delete the file to
force everyone to log in again.

### Migrating from the old cookie-header setup

Existing configs with a `Cookie: _syslog=...` header no longer work. On each
machine: `claude mcp remove syslog --scope user`, then redo step 2.

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

## Syslog receiver (Rust / io_uring)

`syslog-receiver-rs/` is the syslog ingest service: UDP/TCP `:514`,
RFC3164/5424 parsing, batched ClickHouse inserts into `syslog.logs`, and
`/poll` + `/ws` + `/stream` on `:8888` for the live view. Written in Rust on
[monoio](https://github.com/bytedance/monoio), doing all IO — syslog ingest,
the ClickHouse HTTP writes, and the live-view HTTP/WS/SSE server — through
io_uring instead of epoll, thread-per-core.

Requires a kernel with io_uring (5.19+; check `uname -r`) and
`security_opt: seccomp:unconfined` on the container, since Docker's default
seccomp profile blocks the `io_uring_*` syscalls — already set in
`docker-compose.yml` for `syslog-receiver`.

## ClickHouse schema

```sql
-- Main table: partitioned by month, ordered by (hostname, app_name, received_at)
-- TTL: 90 days (configurable in clickhouse/init.sql)
-- Compression: LZ4 for timestamps, ZSTD(3) for messages

-- Materialized view: host_stats_mv_target
-- Pre-aggregated hourly counts per host+severity for fast dashboard queries
```

## Performance

- Rust/io_uring receiver: single binary, one worker thread per core
- Batch writes: 1000 rows or 2s, whichever comes first
- ClickHouse: columnar storage, LZ4/ZSTD compression, MergeTree engine
- Frontend: direct ClickHouse HTTP queries, no intermediate API layer

## Tuning

**Batch size / flush interval** (syslog-receiver-rs/src/clickhouse.rs):
```rust
const BATCH_SIZE: usize = 1000;
const FLUSH_EVERY: Duration = Duration::from_secs(2);
```

**Worker threads** (env `WORKERS`, default: one per CPU core):
```bash
WORKERS=4
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
