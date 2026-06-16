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

## MCP Server

The MCP server runs as an HTTP service behind oauth2-proxy, reachable at `/mcp` on the same domain as the frontend. Authentication uses the same GitHub OAuth session cookie as the browser.

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

Add to `.claude/mcp.json` in your project, or to `~/.claude/mcp.json` for global access:

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

The `_syslog` session cookie expires after 7 days. When it does, re-run `stream_host.py` to get a fresh token and update the MCP config.

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
