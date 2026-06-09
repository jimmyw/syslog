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
   ┌────┴────┐
   │         │
frontend   mcp-server
(:8080)    (stdio)
nginx      Node.js MCP server
           5 tools
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

The MCP server uses stdio transport. Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "syslog": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/syslog-stack/docker-compose.yml",
               "exec", "-T", "mcp-server", "node", "index.js"]
    }
  }
}
```

### Available MCP tools

| Tool | Description |
|------|-------------|
| `query_logs` | Flexible log query with filters (host, app, severity, message, time range) |
| `get_stats` | Aggregated counts by host / severity / app / hour |
| `list_hosts` | All known hosts with last-seen, total count, error count |
| `get_log_rate` | Time-series ingestion rate (minute/hour/day buckets) |
| `search_errors` | Recent errors/critical/alerts across all hosts |

### Example MCP prompts

- *"Show me all errors from esp32 devices in the last hour"*
- *"Which host is generating the most logs today?"*
- *"Are there any critical logs from host terra?"*
- *"Show me the log rate for the last 24 hours"*

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
