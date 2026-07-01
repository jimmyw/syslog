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

function toChTs(v) {
  // UTC ISO string ("...Z" or "+HH:MM" offset) — strip fractions/Z, keep as UTC
  if (v.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(v)) {
    return v.replace('T', ' ').replace(/\.\d+Z$/, '').replace(/Z$/, '');
  }
  // datetime-local string ("YYYY-MM-DDTHH:MM" — no timezone = local time)
  // Convert from local to UTC for ClickHouse
  if (v.includes('T')) {
    const d = new Date(v); // spec: datetime string without TZ parsed as local
    const p = n => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  }
  // ClickHouse naive UTC string ("YYYY-MM-DD HH:MM:SS.mmm") — strip fractions only
  let s = v.replace(/\.\d+$/, '');
  if (s.length === 16) s += ':00';
  return s;
}

export function buildLogsSQL({ hostname, source_ip, app_name, severity_max, message_contains, since = "1h", from, until, before, limit = 2000 } = {}) {
  const sinceExpr = from
    ? `'${toChTs(from)}'`
    : (relativeToSQL(since) || `'${since}'`);
  const where = [`received_at >= ${sinceExpr}`];
  if (until) where.push(`received_at <= '${toChTs(until)}'`);
  if (before) where.push(`received_at < '${toChTs(before)}'`);
  if (source_ip) where.push(`source_ip = '${source_ip.replace(/'/g, "''")}'`);
  if (hostname) where.push(`hostname LIKE '${hostname.replace(/'/g, "''")}'`);
  if (app_name) where.push(`app_name = '${app_name.replace(/'/g, "''")}'`);
  if (severity_max !== undefined && severity_max !== null) where.push(`severity <= ${severity_max}`);
  if (message_contains) where.push(`positionCaseInsensitive(message, '${message_contains.replace(/'/g, "''")}') > 0`);
  return (
    `SELECT received_at, hostname, app_name, proc_id, severity, severity_name, facility_name, source_ip, message\n` +
    `FROM syslog.logs\n` +
    `WHERE ${where.join("\n  AND ")}\n` +
    `ORDER BY received_at DESC\n` +
    `LIMIT ${Math.min(limit, 2000)}`
  );
}

export const api = {
  async getLogs(params = {}) {
    return chQuery(buildLogsSQL(params));
  },

  async rawQuery(sql) {
    return chQuery(sql.trim());
  },

  async getHosts({ hostname, app_name, severity_max, message_contains, since = "1h", from, until } = {}) {
    const sinceExpr = from
      ? `'${toChTs(from)}'`
      : (relativeToSQL(since) || `'${since}'`);
    const where = [`received_at >= ${sinceExpr}`];
    if (until) where.push(`received_at <= '${toChTs(until)}'`);
    if (hostname) where.push(`hostname LIKE '${hostname.replace(/'/g, "''")}'`);
    if (app_name) where.push(`app_name = '${app_name.replace(/'/g, "''")}'`);
    if (severity_max !== undefined && severity_max !== null) where.push(`severity <= ${severity_max}`);
    if (message_contains) where.push(`positionCaseInsensitive(message, '${message_contains.replace(/'/g, "''")}') > 0`);
    return chQuery(`
      SELECT
        source_ip,
        argMax(hostname, received_at) AS hostname,
        count() AS total,
        max(received_at) AS last_seen,
        countIf(severity <= 3) AS error_count
      FROM syslog.logs
      WHERE ${where.join("\n        AND ")}
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
