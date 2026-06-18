import { useState, useEffect, useLayoutEffect, useRef, useCallback } from "react";
import { api, buildLogsSQL } from "./api";

function filtersFromURL() {
  const p = new URLSearchParams(location.search);
  const f = { since: p.get("since") || "1h" };
  if (p.get("hostname"))          f.hostname          = p.get("hostname");
  if (p.get("source_ip"))         f.source_ip         = p.get("source_ip");
  if (p.get("app_name"))          f.app_name          = p.get("app_name");
  if (p.get("message_contains"))  f.message_contains  = p.get("message_contains");
  const sev = p.get("severity_max");
  if (sev !== null && sev !== "") f.severity_max       = parseInt(sev, 10);
  return f;
}

function sinceToMs(since) {
  const m = (since || "1h").match(/^(\d+)([mhd])$/);
  if (!m) return 3_600_000;
  return parseInt(m[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
}

// Max rows the live view keeps in memory. Matches the server fetch cap
// (buildLogsSQL clamps LIMIT to 2000) and bounds both the rendered list and
// the pending buffer that accumulates while the user is scrolled up.
const MAX_ROWS = 2000;

// Parse a log timestamp to epoch ms. ClickHouse returns naive UTC strings
// ("2026-06-18 12:35:55.605") which JS would otherwise parse as *local*
// time; the live WS feed sends RFC3339 ("...T...Z"). Normalise both to UTC
// so display and the live-window cutoff agree.
function parseTs(s) {
  if (!s) return NaN;
  if (s.includes("T")) return new Date(s).getTime();   // already has zone (WS)
  return new Date(s.replace(" ", "T") + "Z").getTime(); // naive → treat as UTC
}

const SEV_COLOR = {
  emerg:   "#ff2d55",
  alert:   "#ff3b30",
  crit:    "#ff6b35",
  err:     "#ff9500",
  warning: "#ffd60a",
  notice:  "#34c759",
  info:    "#636366",
  debug:   "#3a3a3c",
};
const SEV_ORDER = ["emerg","alert","crit","err","warning","notice","info","debug"];
const SEV_MAX = { emerg:0, alert:1, crit:2, err:3, warning:4, notice:5, info:6, debug:7 };
const SEV_ABBR = { emerg:"EMRG", alert:"ALRT", crit:"CRIT", err:"ERRO", warning:"WARN", notice:"NOTE", info:"INFO", debug:"DEBG" };

function SevBadge({ name }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700,
      fontFamily: "monospace",
      display: "inline-block", width: "3.2em", textAlign: "center",
      padding: "1px 0", borderRadius: 3,
      background: SEV_COLOR[name] || "#444",
      color: ["emerg","alert","crit","err"].includes(name) ? "#fff" : name === "warning" ? "#000" : "#fff",
      flexShrink: 0,
    }}>{SEV_ABBR[name] || name.slice(0,4).toUpperCase()}</span>
  );
}

function LogRow({ log, highlight, tightBottom }) {
  const d = new Date(parseTs(log.received_at));
  const ts = d.toLocaleTimeString("sv-SE", { hour12: false }) +
    "." + String(d.getMilliseconds()).padStart(3, "0");
  const msg = highlight
    ? log.message.replace(new RegExp(`(${highlight})`, "gi"), "§§$1§§")
    : log.message;

  return (
    <div style={{
      display: "flex", gap: 8, alignItems: "baseline",
      padding: "2px 12px",
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      fontSize: 12, lineHeight: "1.6",
      borderBottom: tightBottom ? "none" : "1px solid #1c1c1e",
      background: SEV_MAX[log.severity_name] <= 3 ? "rgba(255,60,0,0.04)" : "transparent",
    }}>
      <span style={{ color: "#48484a", flexShrink: 0, fontSize: 11 }}>{ts}</span>
      <SevBadge name={log.severity_name} />
      <span style={{ color: "#8e8e93", flexShrink: 0, width: "14ch", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        title={log.hostname}>{log.hostname}</span>
      <span style={{ color: "#3a3a3c", flexShrink: 0, width: "16ch", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11 }}
        title={log.source_ip}>{log.source_ip && log.source_ip !== log.hostname ? log.source_ip : ""}</span>
      <span style={{ color: "#5e5ce6", flexShrink: 0, width: "32ch", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        title={log.app_name}>{log.app_name}</span>
      <span style={{ color: "#ebebf5cc", flex: 1, wordBreak: "break-all" }}>
        {highlight ? msg.split("§§").map((part, i) =>
          i % 2 === 1
            ? <mark key={i} style={{ background: "#ffd60a33", color: "#ffd60a" }}>{part}</mark>
            : part
        ) : msg}
      </span>
    </div>
  );
}

function HostList({ hosts, selectedSourceIP, onSelect }) {
  return (
    <div style={{ width: 220, flexShrink: 0, borderRight: "1px solid #2c2c2e", overflowY: "auto" }}>
      <div style={{ padding: "10px 12px 6px", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#636366", textTransform: "uppercase" }}>
        Hosts ({hosts.length})
      </div>
      <div
        onClick={() => onSelect(null)}
        style={{
          padding: "6px 12px", cursor: "pointer", fontSize: 12,
          background: selectedSourceIP === null ? "#2c2c2e" : "transparent",
          color: selectedSourceIP === null ? "#fff" : "#ebebf5",
          display: "flex", justifyContent: "space-between",
        }}
      >
        <span>All hosts</span>
      </div>
      {hosts.map((h) => {
        const label = h.hostname !== h.source_ip ? h.hostname : h.source_ip;
        const sublabel = h.hostname !== h.source_ip ? h.source_ip : null;
        return (
          <div
            key={h.source_ip}
            onClick={() => onSelect(h.source_ip)}
            style={{
              padding: "5px 12px 6px", cursor: "pointer", fontSize: 12,
              background: selectedSourceIP === h.source_ip ? "#2c2c2e" : "transparent",
              color: "#ebebf5",
            }}
          >
            <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={label}>
              {label}
            </div>
            {sublabel && (
              <div style={{ fontSize: 10, color: "#636366", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {sublabel}
              </div>
            )}
            <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 4, marginTop: 2 }}>
              {parseInt(h.error_count) > 0 && (
                <span style={{ fontSize: 10, background: "#ff3b30", color: "#fff", borderRadius: 3, padding: "0 4px", lineHeight: "14px" }}>
                  {h.error_count}
                </span>
              )}
              <span style={{ fontSize: 10, color: "#48484a" }}>{parseInt(h.total).toLocaleString()}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function QueryPanel({ sql, onRun, loading }) {
  const [text, setText] = useState(sql);
  const [error, setError] = useState(null);
  useEffect(() => { setText(sql); }, [sql]);

  const run = async () => {
    setError(null);
    try { await onRun(text); }
    catch (e) { setError(e.message); }
  };

  return (
    <div style={{ borderBottom: "1px solid #2c2c2e", background: "#080808", padding: "8px 12px", flexShrink: 0 }}>
      <div style={{ display: "flex", gap: 6, marginBottom: 4, alignItems: "center" }}>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#636366", textTransform: "uppercase", fontFamily: "monospace" }}>SQL</span>
        <button
          onClick={run}
          disabled={loading}
          style={{ ...btnStyle, background: "#0d2b0d", color: "#30d158", border: "1px solid #1a3d1a" }}
        >
          ▶ run
        </button>
        <span style={{ fontSize: 10, color: "#636366", fontFamily: "monospace" }}>or Ctrl+Enter</span>
        {error && <span style={{ fontSize: 11, color: "#ff453a", fontFamily: "monospace", marginLeft: 8 }}>{error}</span>}
      </div>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); run(); } }}
        style={{
          width: "100%", boxSizing: "border-box",
          background: "#1c1c1e", border: "1px solid #2c2c2e", borderRadius: 4,
          color: "#ebebf5", fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 11, lineHeight: "1.5", padding: "6px 8px",
          resize: "vertical", minHeight: 80, outline: "none",
        }}
        rows={4}
      />
    </div>
  );
}

function Toolbar({ filters, setFilters, loading, onRefresh, onClear, onResetCleared, liveMode, setLiveMode, showSql, onToggleSql }) {
  return (
    <div style={{
      display: "flex", gap: 8, padding: "8px 12px", borderBottom: "1px solid #2c2c2e",
      alignItems: "center", flexWrap: "wrap",
    }}>
      <input
        placeholder="search message…"
        value={filters.message_contains || ""}
        onChange={(e) => setFilters((f) => ({ ...f, message_contains: e.target.value }))}
        style={inputStyle}
      />
      <input
        placeholder="hostname…"
        value={filters.hostname || ""}
        onChange={(e) => setFilters((f) => ({ ...f, hostname: e.target.value || undefined }))}
        style={{ ...inputStyle, width: 140 }}
      />
      <input
        placeholder="app name…"
        value={filters.app_name || ""}
        onChange={(e) => setFilters((f) => ({ ...f, app_name: e.target.value }))}
        style={{ ...inputStyle, width: 120 }}
      />
      <select
        value={filters.severity_max ?? ""}
        onChange={(e) => setFilters((f) => ({ ...f, severity_max: e.target.value === "" ? null : parseInt(e.target.value) }))}
        style={{ ...inputStyle, width: 110 }}
      >
        <option value="">all severities</option>
        {SEV_ORDER.map((s, i) => (
          <option key={s} value={i}>{s} ({i})</option>
        ))}
      </select>
      <select
        value={filters.since || "1h"}
        onChange={(e) => { onResetCleared(); setFilters((f) => ({ ...f, since: e.target.value })); }}
        style={{ ...inputStyle, width: 90 }}
      >
        {["5m","15m","1h","6h","24h","7d"].map(v => <option key={v} value={v}>{v}</option>)}
      </select>
      <button
        onClick={() => setLiveMode((v) => !v)}
        style={{
          ...btnStyle,
          background: liveMode ? "#30d158" : "#2c2c2e",
          color: liveMode ? "#000" : "#ebebf5",
        }}
      >
        {liveMode ? "● LIVE" : "LIVE"}
      </button>
      <button onClick={onClear} disabled={loading} style={{ ...btnStyle, color: "#ff453a" }}>
        ✕ clear
      </button>
      <button onClick={onRefresh} disabled={loading} style={btnStyle}>
        {loading ? "…" : "↺"}
      </button>
      <button
        onClick={onToggleSql}
        style={{ ...btnStyle, marginLeft: "auto", background: showSql ? "#1c2b3a" : "#2c2c2e", color: showSql ? "#64d2ff" : "#ebebf5" }}
      >
        SQL
      </button>
    </div>
  );
}

const inputStyle = {
  background: "#1c1c1e", border: "1px solid #2c2c2e", borderRadius: 5,
  color: "#ebebf5", padding: "4px 8px", fontSize: 12,
  fontFamily: "'JetBrains Mono', monospace", outline: "none", width: 200,
};
const btnStyle = {
  background: "#2c2c2e", border: "none", borderRadius: 5,
  color: "#ebebf5", padding: "4px 10px", fontSize: 12,
  cursor: "pointer", fontFamily: "'JetBrains Mono', monospace",
};

function StatsBar({ stats }) {
  if (!stats) return null;
  const sevColors = { emerg:"#ff2d55", alert:"#ff3b30", crit:"#ff6b35", err:"#ff9500", warning:"#ffd60a", notice:"#34c759", info:"#636366", debug:"#3a3a3c" };
  const total = stats.bySeverity.reduce((s, r) => s + parseInt(r.count), 0);
  return (
    <div style={{ display: "flex", gap: 12, padding: "6px 12px", borderBottom: "1px solid #2c2c2e", alignItems: "center", flexWrap: "wrap" }}>
      <span style={{ fontSize: 10, color: "#636366", fontFamily: "monospace" }}>last window:</span>
      {stats.bySeverity.map((r) => (
        <span key={r.severity_name} style={{ fontSize: 11, fontFamily: "monospace", color: sevColors[r.severity_name] || "#fff" }}>
          {r.severity_name} <b style={{ color: "#fff" }}>{parseInt(r.count).toLocaleString()}</b>
        </span>
      ))}
      <span style={{ fontSize: 10, color: "#636366", marginLeft: "auto", fontFamily: "monospace" }}>
        total {total.toLocaleString()}
      </span>
    </div>
  );
}

export default function App() {
  const [logs, setLogs] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState(filtersFromURL);
  const [loading, setLoading] = useState(false);
  const [liveMode, setLiveMode] = useState(() => new URLSearchParams(location.search).get("live") === "1");
  const [autoScroll, setAutoScroll] = useState(true);
  const [clearedAt, setClearedAt] = useState(null);
  const [showSql, setShowSql] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const [sql, setSql] = useState(() => buildLogsSQL({ since: "1h" }));
  const [pendingCount, setPendingCount] = useState(0);
  const bottomRef = useRef(null);
  const atBottomRef = useRef(true);
  const pendingRef = useRef([]);
  const clearedAtRef = useRef(null);
  const filtersRef = useRef(filters);
  useEffect(() => { clearedAtRef.current = clearedAt; }, [clearedAt]);
  useEffect(() => { filtersRef.current = filters; }, [filters]);
  useEffect(() => { setSql(buildLogsSQL({ ...filters, from: clearedAt })); }, [filters, clearedAt]);

  useEffect(() => {
    const p = new URLSearchParams();
    if (filters.since && filters.since !== "1h") p.set("since", filters.since);
    if (filters.hostname)          p.set("hostname",          filters.hostname);
    if (filters.source_ip)         p.set("source_ip",         filters.source_ip);
    if (filters.app_name)          p.set("app_name",          filters.app_name);
    if (filters.message_contains)  p.set("message_contains",  filters.message_contains);
    if (filters.severity_max != null) p.set("severity_max",   filters.severity_max);
    if (liveMode)                  p.set("live",              "1");
    const qs = p.toString();
    history.replaceState(null, "", qs ? `?${qs}` : location.pathname);
  }, [filters, liveMode]);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const [logData, hostData, statsData] = await Promise.all([
        api.getLogs({ ...filters, from: clearedAt }),
        api.getHosts({ ...filters, source_ip: undefined, from: clearedAt }),
        api.getStats(filters.since || "1h"),
      ]);
      setTruncated(logData.length >= MAX_ROWS);
      // A fresh query (mount, filter/device/window change) shows newest at
      // the bottom and follows the tail until the user scrolls up. Drop any
      // lines buffered against the previous query.
      pendingRef.current = [];
      setPendingCount(0);
      atBottomRef.current = true;
      setAutoScroll(true);
      setLogs(logData.reverse());
      setHosts(hostData);
      setStats(statsData);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [filters, clearedAt]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  useEffect(() => {
    if (!liveMode) return;
    let ws = null;
    let active = true;
    let retryTimer = null;

    function connect() {
      if (!active) return;
      const f = filtersRef.current;
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const params = new URLSearchParams();
      if (f.hostname)         params.set("hostname",         f.hostname);
      if (f.source_ip)        params.set("source_ip",        f.source_ip);
      if (f.app_name)         params.set("app_name",         f.app_name);
      if (f.message_contains) params.set("message_contains", f.message_contains);
      if (f.severity_max != null) params.set("severity_max", f.severity_max);
      const qs = params.toString();
      ws = new WebSocket(`${proto}//${location.host}/ws${qs ? "?" + qs : ""}`);

      ws.onmessage = (e) => {
        const log = JSON.parse(e.data);
        const ca = clearedAtRef.current;
        const caMs = ca ? parseTs(ca) : null;
        const cutoffMs = Date.now() - sinceToMs(filtersRef.current.since);
        const logMs = parseTs(log.received_at);
        if (logMs < cutoffMs) return;
        if (caMs && logMs < caMs) return;

        // While the user is scrolled up reading history, leave the rendered
        // list untouched (any change above the viewport would shift it and
        // fight their scroll) and stash incoming lines in a buffer. Keep only
        // the newest MAX_ROWS so a busy feed can't grow memory without bound.
        // The buffer is flushed when they return to the bottom.
        if (!atBottomRef.current) {
          const buf = pendingRef.current;
          buf.push(log);
          if (buf.length > MAX_ROWS) buf.splice(0, buf.length - MAX_ROWS);
          setPendingCount(buf.length);
          return;
        }

        setLogs((prev) => {
          const combined = [...prev, log];
          const trimmed = combined.filter(l => parseTs(l.received_at) >= cutoffMs);
          return trimmed.length > MAX_ROWS ? trimmed.slice(-MAX_ROWS) : trimmed;
        });
      };

      ws.onerror = () => ws.close();
      ws.onclose = () => { if (active) retryTimer = setTimeout(connect, 1000); };
    }

    connect();
    return () => {
      active = false;
      clearTimeout(retryTimer);
      ws?.close();
    };
  }, [liveMode, filters]);

  // Only follow new output when the user is parked at the bottom. Read the
  // live position from a ref (kept in sync by onScroll) rather than the
  // autoScroll state: the programmatic scroll below itself fires onScroll,
  // and reading stale state here would re-pin the view and fight a user who
  // is scrolling up through a busy live feed.
  useLayoutEffect(() => {
    if (atBottomRef.current && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "instant" });
    }
  }, [logs]);

  // Return to the tail: merge any buffered lines back in (applying the same
  // window age-out and cap as the live path), resume following, and pin to
  // the bottom. Used by the scroll-to-bottom button and when the user scrolls
  // down to the end manually.
  const flushPending = useCallback(() => {
    const buf = pendingRef.current;
    pendingRef.current = [];
    setPendingCount(0);
    atBottomRef.current = true;
    setAutoScroll(true);
    if (buf.length) {
      const cutoffMs = Date.now() - sinceToMs(filtersRef.current.since);
      setLogs((prev) => {
        const combined = [...prev, ...buf];
        const trimmed = combined.filter(l => parseTs(l.received_at) >= cutoffMs);
        return trimmed.length > MAX_ROWS ? trimmed.slice(-MAX_ROWS) : trimmed;
      });
    } else {
      // No buffered lines means setLogs won't run, so the layout effect won't
      // fire — scroll to the bottom explicitly.
      bottomRef.current?.scrollIntoView({ behavior: "instant" });
    }
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
    setClearedAt(new Date().toISOString());
  }, []);

  const runSql = useCallback(async (rawSql) => {
    setLoading(true);
    try {
      const data = await api.rawQuery(rawSql);
      setLogs(data);
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: "#000", color: "#ebebf5" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", padding: "0 12px", height: 44, borderBottom: "1px solid #2c2c2e", flexShrink: 0 }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: 14, letterSpacing: "0.05em" }}>
          ⬡ SYSLOG
        </span>
        <span style={{ marginLeft: 8, fontSize: 11, color: "#48484a", fontFamily: "monospace" }}>
          {logs.length} rows
        </span>
        {truncated && !liveMode && (
          <span style={{ marginLeft: 8, fontSize: 11, color: "#ff9500", fontFamily: "monospace" }}
            title="More rows match this window than are shown; only the newest 2000 were loaded.">
            newest 2000 (capped) — narrow the window or filter
          </span>
        )}
      </div>

      <StatsBar stats={stats} />
      <Toolbar
        filters={filters}
        setFilters={setFilters}
        loading={loading}
        onRefresh={fetchLogs}
        onClear={clearLogs}
        onResetCleared={() => setClearedAt(null)}
        liveMode={liveMode}
        setLiveMode={setLiveMode}
        showSql={showSql}
        onToggleSql={() => setShowSql((v) => !v)}
      />
      {showSql && <QueryPanel sql={sql} onRun={runSql} loading={loading} />}

      {/* Body */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        <HostList
          hosts={hosts}
          selectedSourceIP={filters.source_ip || null}
          onSelect={(ip) => setFilters((f) => ({ ...f, source_ip: ip || undefined }))}
        />

        <div
          style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column" }}
          onScroll={(e) => {
            const el = e.currentTarget;
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
            atBottomRef.current = atBottom;
            setAutoScroll(atBottom);
            // Reaching the tail resumes following; drain anything buffered
            // while scrolled up.
            if (atBottom && pendingRef.current.length) flushPending();
          }}
        >
          {logs.length === 0 && !loading && (
            <div style={{ color: "#636366", fontFamily: "monospace", fontSize: 13, padding: 24 }}>
              No logs match your filters.
            </div>
          )}
          {logs.map((log, i) => {
            const ms = parseTs(log.received_at);
            const nextMs = i < logs.length - 1 ? parseTs(logs[i + 1].received_at) : null;
            const tightBottom = nextMs !== null && logs[i + 1].hostname === log.hostname && nextMs - ms < 100;
            return (
              <LogRow key={i} log={log} highlight={filters.message_contains} tightBottom={tightBottom} />
            );
          })}
          <div ref={bottomRef} />
        </div>
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && (
        <button
          onClick={flushPending}
          style={{
            ...btnStyle, position: "fixed", bottom: 16, right: 16,
            background: pendingCount > 0 ? "#0d2b0d" : "#1c1c1e",
            color: pendingCount > 0 ? "#30d158" : "#ebebf5",
            border: `1px solid ${pendingCount > 0 ? "#1a3d1a" : "#2c2c2e"}`,
          }}
        >
          ↓ {pendingCount > 0
            ? `${pendingCount >= MAX_ROWS ? MAX_ROWS.toLocaleString() + "+" : pendingCount.toLocaleString()} new line${pendingCount === 1 ? "" : "s"}`
            : "scroll to bottom"}
        </button>
      )}
    </div>
  );
}
