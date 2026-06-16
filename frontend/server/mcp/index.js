import { randomUUID } from "node:crypto";
import { createClient } from "@clickhouse/client";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";

const app = express();
app.use(express.json());

const transports = new Map(); // sessionId -> StreamableHTTPServerTransport

function createClickHouseClient() {
  return createClient({
    url: `http://${process.env.CLICKHOUSE_HOST || "clickhouse"}:8123`,
    database: "syslog",
    clickhouse_settings: { output_format_json_quote_64bit_integers: 0 },
  });
}

function parseRelativeTime(t) {
  if (!t) return null;
  const m = t.match(/^(\d+)([mhd])$/);
  if (!m) return t; // assume ISO
  const [, n, unit] = m;
  const secs = { m: 60, h: 3600, d: 86400 }[unit] * parseInt(n);
  return new Date(Date.now() - secs * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
}

function timeClause(since, until, col = "received_at") {
  const clauses = [];
  const s = parseRelativeTime(since || "7d");
  if (s) clauses.push(`${col} >= '${s}'`);
  if (until) clauses.push(`${col} <= '${parseRelativeTime(until)}'`);
  return clauses;
}

function buildServer() {
  const ch = createClickHouseClient();

  const server = new Server(
    { name: "syslog-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "query_logs",
        description:
          "Query syslog entries with flexible filters. Returns structured log rows.",
        inputSchema: {
          type: "object",
          properties: {
            hostname: { type: "string", description: "Filter by hostname (supports LIKE patterns, e.g. 'esp32%')" },
            app_name: { type: "string", description: "Filter by application name" },
            severity: { type: "string", description: "Filter by severity: emerg,alert,crit,err,warning,notice,info,debug" },
            severity_max: { type: "number", description: "Max severity number (0=emerg..7=debug). E.g. 3 = err and worse" },
            message_contains: { type: "string", description: "Substring to search in message body" },
            source_ip: { type: "string", description: "Filter by source IP" },
            since: { type: "string", description: "Start time, ISO8601 or relative like '1h', '30m', '7d'" },
            until: { type: "string", description: "End time, ISO8601" },
            limit: { type: "number", description: "Max rows to return (default 100, max 1000)" },
          },
        },
      },
      {
        name: "get_stats",
        description: "Get log statistics: counts by host, severity, or time bucket.",
        inputSchema: {
          type: "object",
          properties: {
            group_by: {
              type: "string",
              enum: ["hostname", "severity", "app_name", "hour", "source_ip"],
              description: "Dimension to group by",
            },
            since: { type: "string", description: "Relative or absolute start time" },
            hostname: { type: "string", description: "Filter to specific host" },
            limit: { type: "number", description: "Max groups (default 20)" },
          },
          required: ["group_by"],
        },
      },
      {
        name: "list_hosts",
        description: "List all known hostnames that have sent logs, with last-seen time and total count.",
        inputSchema: {
          type: "object",
          properties: {
            since: { type: "string", description: "Only hosts active since this time (default 7d)" },
          },
        },
      },
      {
        name: "get_log_rate",
        description: "Get log ingestion rate over time as a time series (useful for spike detection).",
        inputSchema: {
          type: "object",
          properties: {
            bucket: { type: "string", enum: ["minute", "hour", "day"], description: "Time bucket size" },
            hostname: { type: "string", description: "Filter to specific host" },
            since: { type: "string", description: "Start of range (default 24h)" },
          },
        },
      },
      {
        name: "search_errors",
        description: "Quickly find recent error/critical/alert/emergency log entries across all hosts.",
        inputSchema: {
          type: "object",
          properties: {
            since: { type: "string", description: "How far back to search (default 1h)" },
            hostname: { type: "string", description: "Limit to specific host" },
            limit: { type: "number", description: "Max results (default 50)" },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    try {
      let result;

      if (name === "query_logs") {
        const limit = Math.min(args.limit || 100, 1000);
        const where = [...timeClause(args.since, args.until)];
        if (args.hostname) where.push(`hostname LIKE '${args.hostname.replace(/'/g, "''")}'`);
        if (args.app_name) where.push(`app_name = '${args.app_name.replace(/'/g, "''")}'`);
        if (args.severity) where.push(`severity_name = '${args.severity}'`);
        if (args.severity_max !== undefined) where.push(`severity <= ${args.severity_max}`);
        if (args.message_contains) where.push(`positionCaseInsensitive(message, '${args.message_contains.replace(/'/g, "''")}') > 0`);
        if (args.source_ip) where.push(`source_ip = '${args.source_ip}'`);

        const sql = `
          SELECT received_at, hostname, app_name, severity_name, facility_name, source_ip, message
          FROM syslog.logs
          ${where.length ? "WHERE " + where.join(" AND ") : ""}
          ORDER BY received_at DESC
          LIMIT ${limit}
        `;
        const rows = await ch.query({ query: sql, format: "JSONEachRow" });
        result = await rows.json();
      }

      else if (name === "get_stats") {
        const limit = args.limit || 20;
        const groupCol = args.group_by === "hour" ? "toStartOfHour(received_at) AS hour" : args.group_by;
        const orderCol = args.group_by === "hour" ? "hour" : args.group_by;
        const where = [...timeClause(args.since || "24h", null)];
        if (args.hostname) where.push(`hostname = '${args.hostname}'`);

        const sql = `
          SELECT ${groupCol}, count() AS count
          FROM syslog.logs
          ${where.length ? "WHERE " + where.join(" AND ") : ""}
          GROUP BY ${orderCol}
          ORDER BY count DESC
          LIMIT ${limit}
        `;
        const rows = await ch.query({ query: sql, format: "JSONEachRow" });
        result = await rows.json();
      }

      else if (name === "list_hosts") {
        const where = timeClause(args.since || "7d", null);
        const sql = `
          SELECT hostname, source_ip,
                 count() AS total_logs,
                 max(received_at) AS last_seen,
                 min(received_at) AS first_seen
          FROM syslog.logs
          ${where.length ? "WHERE " + where.join(" AND ") : ""}
          GROUP BY hostname, source_ip
          ORDER BY last_seen DESC
        `;
        const rows = await ch.query({ query: sql, format: "JSONEachRow" });
        result = await rows.json();
      }

      else if (name === "get_log_rate") {
        const bucketFn = { minute: "toStartOfMinute", hour: "toStartOfHour", day: "toStartOfDay" }[args.bucket || "hour"];
        const where = timeClause(args.since || "24h", null);
        if (args.hostname) where.push(`hostname = '${args.hostname}'`);
        const sql = `
          SELECT ${bucketFn}(received_at) AS bucket, count() AS count
          FROM syslog.logs
          ${where.length ? "WHERE " + where.join(" AND ") : ""}
          GROUP BY bucket ORDER BY bucket ASC
        `;
        const rows = await ch.query({ query: sql, format: "JSONEachRow" });
        result = await rows.json();
      }

      else if (name === "search_errors") {
        const limit = Math.min(args.limit || 50, 500);
        const where = ["severity <= 3", ...timeClause(args.since || "1h", null)];
        if (args.hostname) where.push(`hostname = '${args.hostname}'`);
        const sql = `
          SELECT received_at, hostname, app_name, severity_name, message, source_ip
          FROM syslog.logs
          WHERE ${where.join(" AND ")}
          ORDER BY received_at DESC
          LIMIT ${limit}
        `;
        const rows = await ch.query({ query: sql, format: "JSONEachRow" });
        result = await rows.json();
      }

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  });

  return server;
}

app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId).handleRequest(req, res, req.body);
    return;
  }
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => transports.set(id, transport),
  });
  transport.onclose = () => {
    if (transport.sessionId) transports.delete(transport.sessionId);
  };
  const server = buildServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", async (req, res) => {
  const id = req.headers["mcp-session-id"];
  if (id && transports.has(id)) {
    await transports.get(id).handleRequest(req, res);
  } else {
    res.status(400).json({ error: "no session" });
  }
});

app.delete("/mcp", async (req, res) => {
  const id = req.headers["mcp-session-id"];
  if (id && transports.has(id)) {
    await transports.get(id).handleRequest(req, res);
    transports.delete(id);
  } else {
    res.status(404).end();
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`syslog MCP HTTP server listening on port ${PORT}`);
});
