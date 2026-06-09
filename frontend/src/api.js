const CH_URL = import.meta.env.VITE_CLICKHOUSE_URL || "/ch";

async function chQuery(sql, format = "JSONEachRow") {
  const params = new URLSearchParams({ query: sql, default_format: format, database: "syslog" });
  const res = await fetch(`${CH_URL}/?${params}`, { method: "GET" });
  if (!res.ok) throw new Error(await res.text());
  const text = await res.text();
  if (format === "JSONEachRow") {
    return text
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  }
  return text;
}

function relativeToSQL(rel) {
  if (!rel) return null;
  const m = rel.match(/^(\d+)([mhd])$/);
  if (!m) return rel;
  const [, n, unit] = m;
  const map = { m: "MINUTE", h: "HOUR", d: "DAY" };
  return `now() - INTERVAL ${n} ${map[unit]}`;
}

export const api = {
  async getLogs({ hostname, source_ip, app_name, severity_max, message_contains, since = "1h", from, until, limit = 200 } = {}) {
    const sinceExpr = from
      ? `'${from.replace('T', ' ').replace(/\.\d+Z$/, '')}'`
      : (relativeToSQL(since) || `'${since}'`);
    const where = [`received_at >= ${sinceExpr}`];
    if (until) where.push(`received_at <= '${until}'`);
    if (source_ip) where.push(`source_ip = '${source_ip.replace(/'/g, "''")}'`);
    if (hostname) where.push(`hostname LIKE '${hostname.replace(/'/g, "''")}'`);
    if (app_name) where.push(`app_name = '${app_name.replace(/'/g, "''")}'`);
    if (severity_max !== undefined && severity_max !== null) where.push(`severity <= ${severity_max}`);
    if (message_contains) where.push(`positionCaseInsensitive(message, '${message_contains.replace(/'/g, "''")}') > 0`);

    return chQuery(`
      SELECT received_at, hostname, app_name, proc_id, severity, severity_name, facility_name, source_ip, message
      FROM syslog.logs
      WHERE ${where.join(" AND ")}
      ORDER BY received_at DESC
      LIMIT ${Math.min(limit, 2000)}
    `);
  },

  async getHosts() {
    return chQuery(`
      SELECT
        source_ip,
        argMax(hostname, received_at) AS hostname,
        count() AS total,
        max(received_at) AS last_seen,
        countIf(severity <= 3) AS error_count
      FROM syslog.logs
      WHERE received_at >= now() - INTERVAL 7 DAY
      GROUP BY source_ip
      ORDER BY last_seen DESC
    `);
  },

  async getStats(since = "24h") {
    const t = relativeToSQL(since);
    const [byHost, bySeverity, rate] = await Promise.all([
      chQuery(`
        SELECT hostname, count() AS count
        FROM syslog.logs WHERE received_at >= ${t}
        GROUP BY hostname ORDER BY count DESC LIMIT 20
      `),
      chQuery(`
        SELECT severity_name, severity, count() AS count
        FROM syslog.logs WHERE received_at >= ${t}
        GROUP BY severity_name, severity ORDER BY severity
      `),
      chQuery(`
        SELECT toStartOfHour(received_at) AS hour, count() AS count
        FROM syslog.logs WHERE received_at >= ${t}
        GROUP BY hour ORDER BY hour ASC
      `),
    ]);
    return { byHost, bySeverity, rate };
  },

  async getRecentErrors(limit = 50) {
    return chQuery(`
      SELECT received_at, hostname, app_name, severity_name, message, source_ip
      FROM syslog.logs
      WHERE severity <= 3 AND received_at >= now() - INTERVAL 1 HOUR
      ORDER BY received_at DESC
      LIMIT ${limit}
    `);
  },
};
