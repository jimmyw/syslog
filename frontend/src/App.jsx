import { useState, useEffect, useRef, useCallback } from "react";
import { api, buildLogsSQL } from "./api";

function sinceToMs(since) {
  const m = (since || "1h").match(/^(\d+)([mhd])$/);
  if (!m) return 3_600_000;
  return parseInt(m[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
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

function SevBadge({ name }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: "0.06em",
      padding: "1px 5px", borderRadius: 3,
      background: SEV_COLOR[name] || "#444",
      color: ["emerg","alert","crit","err"].includes(name) ? "#fff" : name === "warning" ? "#000" : "#fff",
      textTransform: "uppercase",
      flexShrink: 0,
    }}>{name}</span>
  );
}

function LogRow({ log, highlight, tightBottom }) {
  const ts = new Date(log.received_at).toLocaleTimeString("sv-SE", { hour12: false }) +
    "." + String(new Date(log.received_at).getMilliseconds()).padStart(3, "0");
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
      <span style={{ color: "#8e8e93", flexShrink: 0, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        title={log.hostname}>{log.hostname}</span>
      {log.source_ip && log.source_ip !== log.hostname && (
        <span style={{ color: "#3a3a3c", flexShrink: 0, maxWidth: 95, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11 }}
          title={log.source_ip}>{log.source_ip}</span>
      )}
      <span style={{ color: "#5e5ce6", flexShrink: 0, maxWidth: 100, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
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
              padding: "5px 12px", cursor: "pointer", fontSize: 12,
              background: selectedSourceIP === h.source_ip ? "#2c2c2e" : "transparent",
              color: "#ebebf5",
              display: "flex", justifyContent: "space-between", alignItems: "center",
              gap: 4,
            }}
          >
            <div style={{ overflow: "hidden", flex: 1, minWidth: 0 }}>
              <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={label}>
                {label}
              </div>
              {sublabel && (
                <div style={{ fontSize: 10, color: "#48484a", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {sublabel}
                </div>
              )}
            </div>
            <span style={{ display: "flex", gap: 4, flexShrink: 0 }}>
              {parseInt(h.error_count) > 0 && (
                <span style={{ fontSize: 10, background: "#ff3b30", color: "#fff", borderRadius: 3, padding: "0 4px" }}>
                  {h.error_count}
                </span>
              )}
              <span style={{ fontSize: 10, color: "#48484a" }}>{parseInt(h.total).toLocaleString()}</span>
            </span>
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
  const [filters, setFilters] = useState({ since: "1h" });
  const [loading, setLoading] = useState(false);
  const [liveMode, setLiveMode] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [clearedAt, setClearedAt] = useState(null);
  const [showSql, setShowSql] = useState(false);
  const [sql, setSql] = useState(() => buildLogsSQL({ since: "1h" }));
  const bottomRef = useRef(null);
  const clearedAtRef = useRef(null);
  const filtersRef = useRef(filters);
  useEffect(() => { clearedAtRef.current = clearedAt; }, [clearedAt]);
  useEffect(() => { filtersRef.current = filters; }, [filters]);
  useEffect(() => { setSql(buildLogsSQL({ ...filters, from: clearedAt })); }, [filters, clearedAt]);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const [logData, hostData, statsData] = await Promise.all([
        api.getLogs({ ...filters, from: clearedAt }),
        api.getHosts({ ...filters, source_ip: undefined, from: clearedAt }),
        api.getStats(filters.since || "1h"),
      ]);
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
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${location.host}/ws`);

      ws.onmessage = (e) => {
        const log = JSON.parse(e.data);
        setLogs((prev) => {
          const f = filtersRef.current;
          const ca = clearedAtRef.current;
          const caMs = ca ? new Date(ca).getTime() : null;
          const cutoffMs = Date.now() - sinceToMs(f.since);
          const logMs = new Date(log.received_at).getTime();
          if (logMs < cutoffMs) return prev;
          if (caMs && logMs < caMs) return prev;
          if (f.source_ip && log.source_ip !== f.source_ip) return prev;
          if (f.hostname && !log.hostname.toLowerCase().includes(f.hostname.toLowerCase())) return prev;
          if (f.app_name && log.app_name !== f.app_name) return prev;
          if (f.severity_max != null && log.severity > f.severity_max) return prev;
          if (f.message_contains && !log.message.toLowerCase().includes(f.message_contains.toLowerCase())) return prev;
          const combined = [...prev, log].filter(l => new Date(l.received_at).getTime() >= cutoffMs);
          return combined.length > 500 ? combined.slice(-500) : combined;
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
  }, [liveMode]);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "instant" });
    }
  }, [logs, autoScroll]);

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
            setAutoScroll(el.scrollHeight - el.scrollTop - el.clientHeight < 80);
          }}
        >
          {logs.length === 0 && !loading && (
            <div style={{ color: "#636366", fontFamily: "monospace", fontSize: 13, padding: 24 }}>
              No logs match your filters.
            </div>
          )}
          {logs.map((log, i) => {
            const ms = new Date(log.received_at).getTime();
            const nextMs = i < logs.length - 1 ? new Date(logs[i + 1].received_at).getTime() : null;
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
          onClick={() => { setAutoScroll(true); bottomRef.current?.scrollIntoView({ behavior: "instant" }); }}
          style={{ ...btnStyle, position: "fixed", bottom: 16, right: 16, background: "#1c1c1e", border: "1px solid #2c2c2e" }}
        >
          ↓ scroll to bottom
        </button>
      )}
    </div>
  );
}
