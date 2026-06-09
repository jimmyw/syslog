CREATE DATABASE IF NOT EXISTS syslog;

CREATE TABLE IF NOT EXISTS syslog.logs
(
    received_at   DateTime64(3) CODEC(Delta, ZSTD(1)),
    facility      UInt8,
    facility_name LowCardinality(String),
    severity      UInt8,
    severity_name LowCardinality(String),
    hostname      LowCardinality(String),
    app_name      LowCardinality(String),
    proc_id       String CODEC(ZSTD(1)),
    msg_id        String CODEC(ZSTD(1)),
    message       String CODEC(ZSTD(3)),
    source_ip     LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(received_at)
ORDER BY (hostname, app_name, received_at)
TTL toDateTime(received_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192,
         merge_with_ttl_timeout = 3600;

-- Materialized view for per-host stats (fast dashboard aggregations)
CREATE TABLE IF NOT EXISTS syslog.host_stats_mv_target
(
    hour        DateTime,
    hostname    LowCardinality(String),
    severity    UInt8,
    count       UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, hostname, severity);

CREATE MATERIALIZED VIEW IF NOT EXISTS syslog.host_stats_mv
TO syslog.host_stats_mv_target
AS SELECT
    toStartOfHour(received_at) AS hour,
    hostname,
    severity,
    count() AS count
FROM syslog.logs
GROUP BY hour, hostname, severity;
