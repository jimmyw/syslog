import { useState, useEffect, useLayoutEffect, useRef, useCallback } from "react";
import { api, buildLogsSQL } from "./api";

function filtersFromURL() {
  const p = new URLSearchParams(location.search);
  const f = { since: p.get("since") || "1h" };
  if (p.get("hostname"))          f.hostname          = p.get("hostname");
  if (p.get("source_ip"))         f.source_ip         = p.get("source_ip");
  if (p.get("app_name"))          f.app_name          = p.get("app_name");
  if (p.get("message_contains"))  f.message_contains  = p.get("message_contains");
  if (p.get("from_time"))         f.fromTime          = p.get("from_time");
  if (p.get("until_time"))        f.untilTime         = p.get("until_time");
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

function SevBadge({ name, onClick }) {
  return (
    <span onClick={onClick} style={{
      fontSize: 10, fontWeight: 700,
      fontFamily: "monospace",
      display: "inline-block", width: "3.2em", textAlign: "center",
      padding: "1px 0", borderRadius: 3,
      background: SEV_COLOR[name] || "#444",
      color: ["emerg","alert","crit","err"].includes(name) ? "#fff" : name === "warning" ? "#000" : "#fff",
      flexShrink: 0,
      cursor: onClick ? "pointer" : "default",
    }}>{SEV_ABBR[name] || name.slice(0,4).toUpperCase()}</span>
  );
}

const today = new Date();
function isSameDay(d) {
  return d.getFullYear() === today.getFullYear() &&
    d.getMonth() === today.getMonth() &&
    d.getDate() === today.getDate();
}

function LogRow({ log, highlight, tightBottom, onFilter }) {
  const d = new Date(parseTs(log.received_at));
  const timePart = d.toLocaleTimeString("sv-SE", { hour12: false }) +
    "." + String(d.getMilliseconds()).padStart(3, "0");
  const ts = isSameDay(d)
    ? timePart
    : d.toLocaleDateString("sv-SE") + " " + timePart;
  const msg = highlight
    ? log.message.replace(new RegExp(`(${highlight})`, "gi"), "§§$1§§")
    : log.message;
  const showIp = log.source_ip && log.source_ip !== log.hostname;

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
      <SevBadge name={log.severity_name}
        onClick={() => onFilter({ severity_max: SEV_MAX[log.severity_name] })} />
      <span
        onClick={() => onFilter({ hostname: log.hostname })}
        title={`filter: hostname = ${log.hostname}`}
        style={{ color: "#8e8e93", flexShrink: 0, width: "14ch", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: "pointer" }}>
        {log.hostname}
      </span>
      <span
        onClick={() => showIp && onFilter({ source_ip: log.source_ip })}
        title={showIp ? `filter: source_ip = ${log.source_ip}` : undefined}
        style={{ color: "#3a3a3c", flexShrink: 0, width: "16ch", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11, cursor: showIp ? "pointer" : "default" }}>
        {showIp ? log.source_ip : ""}
      </span>
      <span
        onClick={() => onFilter({ app_name: log.app_name })}
        title={`filter: app_name = ${log.app_name}`}
        style={{ color: "#5e5ce6", flexShrink: 0, width: "32ch", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: "pointer" }}>
        {log.app_name}
      </span>
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

function TimePicker({ filters, onChange }) {
  const presets = ["5m","15m","1h","6h","24h","7d"];
  const [custom, setCustom] = useState(!!filters.fromTime);
  return (
    <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
      <select
        value={custom ? "custom" : (filters.since || "1h")}
        onChange={(e) => {
          if (e.target.value === "custom") {
            setCustom(true);
          } else {
            setCustom(false);
            onChange({ since: e.target.value, fromTime: undefined, untilTime: undefined });
          }
        }}
        style={{ ...inputStyle, width: 90 }}
      >
        {presets.map(v => <option key={v} value={v}>{v}</option>)}
        <option value="custom">custom…</option>
      </select>
      {custom && (
        <>
          <input
            type="datetime-local"
            value={filters.fromTime || ""}
            onChange={(e) => onChange({ fromTime: e.target.value || undefined })}
            style={{ ...inputStyle, width: 160, colorScheme: "dark" }}
          />
          <span style={{ color: "#636366", fontSize: 11 }}>→</span>
          <input
            type="datetime-local"
            value={filters.untilTime || ""}
            onChange={(e) => onChange({ untilTime: e.target.value || undefined })}
            style={{ ...inputStyle, width: 160, colorScheme: "dark" }}
          />
        </>
      )}
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
      <TimePicker
        filters={filters}
        onChange={(update) => {
          onResetCleared();
          setFilters((f) => ({ ...f, ...update }));
        }}
      />
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
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [liveMode, setLiveMode] = useState(() => new URLSearchParams(location.search).get("live") === "1");
  const [autoScroll, setAutoScroll] = useState(true);
  const [clearedAt, setClearedAt] = useState(null);
  const [showSql, setShowSql] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const [sql, setSql] = useState(() => buildLogsSQL({ since: "1h" }));
  const [pendingCount, setPendingCount] = useState(0);
  const bottomRef = useRef(null);
  const scrollRef = useRef(null);
  const prependScrollHeightRef = useRef(null);
  const atBottomRef = useRef(true);
  const pendingRef = useRef([]);
  const clearedAtRef = useRef(null);
  const filtersRef = useRef(filters);
  useEffect(() => { clearedAtRef.current = clearedAt; }, [clearedAt]);
  useEffect(() => { filtersRef.current = filters; }, [filters]);
  useEffect(() => { setSql(buildLogsSQL({ ...filters, from: filters.fromTime || clearedAt, until: filters.untilTime })); }, [filters, clearedAt]);

  useEffect(() => {
    const p = new URLSearchParams();
    if (filters.since && filters.since !== "1h") p.set("since", filters.since);
    if (filters.hostname)          p.set("hostname",          filters.hostname);
    if (filters.source_ip)         p.set("source_ip",         filters.source_ip);
    if (filters.app_name)          p.set("app_name",          filters.app_name);
    if (filters.message_contains)  p.set("message_contains",  filters.message_contains);
    if (filters.severity_max != null) p.set("severity_max",   filters.severity_max);
    if (filters.fromTime)          p.set("from_time",         filters.fromTime);
    if (filters.untilTime)         p.set("until_time",        filters.untilTime);
    if (liveMode)                  p.set("live",              "1");
    const qs = p.toString();
    history.replaceState(null, "", qs ? `?${qs}` : location.pathname);
  }, [filters, liveMode]);

  const refresh = useCallback(() => setRefreshKey(k => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const from = filters.fromTime || clearedAt;
    const until = filters.untilTime;
    Promise.all([
      api.getLogs({ ...filters, from, until }),
      api.getHosts({ ...filters, source_ip: undefined, from, until }).catch(() => null),
      api.getStats(filters.since || "1h").catch(() => null),
    ]).then(([logData, hostData, statsData]) => {
      if (cancelled) return;
      setTruncated(logData.length >= MAX_ROWS);
      setHasMore(logData.length >= MAX_ROWS);
      pendingRef.current = [];
      setPendingCount(0);
      atBottomRef.current = true;
      setAutoScroll(true);
      setLogs(logData.reverse());
      if (hostData) setHosts(hostData);
      if (statsData) setStats(statsData);
    }).catch(e => {
      if (!cancelled) console.error(e);
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [filters, clearedAt, refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadOlderLogs = useCallback(async () => {
    if (loadingOlder || loading || !hasMore || logs.length === 0) return;
    const oldest = logs[0].received_at;
    setLoadingOlder(true);
    try {
      const older = await api.getLogs({ ...filters, from: filters.fromTime || clearedAt, until: filters.untilTime, before: oldest });
      if (older.length === 0) { setHasMore(false); return; }
      prependScrollHeightRef.current = scrollRef.current?.scrollHeight ?? 0;
      setHasMore(older.length >= MAX_ROWS);
      setLogs(prev => [...older.reverse(), ...prev]);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingOlder(false);
    }
  }, [loadingOlder, loading, hasMore, logs, filters, clearedAt]);

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
    if (prependScrollHeightRef.current !== null && scrollRef.current) {
      scrollRef.current.scrollTop += scrollRef.current.scrollHeight - prependScrollHeightRef.current;
      prependScrollHeightRef.current = null;
      return;
    }
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

  const onFilterRow = useCallback((update) => {
    setFilters(f => {
      const next = { ...f };
      for (const [k, v] of Object.entries(update)) {
        next[k] = f[k] === v ? undefined : v;
      }
      return next;
    });
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
          <span style={{ marginLeft: 8, fontSize: 11, color: "#636366", fontFamily: "monospace" }}>
            newest 2000 — scroll up to load older
          </span>
        )}
      </div>

      <StatsBar stats={stats} />
      <Toolbar
        filters={filters}
        setFilters={setFilters}
        loading={loading}
        onRefresh={refresh}
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
          ref={scrollRef}
          style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column" }}
          onScroll={(e) => {
            const el = e.currentTarget;
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
            atBottomRef.current = atBottom;
            setAutoScroll(atBottom);
            if (atBottom && pendingRef.current.length) flushPending();
            if (el.scrollTop < 200 && hasMore && !loadingOlder && !loading) loadOlderLogs();
          }}
        >
          {loadingOlder && (
            <div style={{ color: "#636366", fontFamily: "monospace", fontSize: 11, padding: "8px 12px", textAlign: "center" }}>
              ↑ loading older…
            </div>
          )}
          {!hasMore && !loadingOlder && logs.length > 0 && (
            <div style={{ color: "#3a3a3c", fontFamily: "monospace", fontSize: 10, padding: "6px 12px", textAlign: "center" }}>
              ─── beginning of results ───
            </div>
          )}
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
              <LogRow key={i} log={log} highlight={filters.message_contains} tightBottom={tightBottom} onFilter={onFilterRow} />
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
