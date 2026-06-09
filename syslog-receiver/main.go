package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type SyslogEntry struct {
	ReceivedAt time.Time
	Facility   uint8
	Severity   uint8
	Hostname   string
	AppName    string
	ProcID     string
	MsgID      string
	Message    string
	SourceIP   string
}

var severityNames = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
var facilityNames = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

func parsePriority(s string) (facility, severity uint8) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 191 {
		return 1, 6
	}
	return uint8(n / 8), uint8(n % 8)
}

func parseSyslog(raw string, srcIP string) SyslogEntry {
	entry := SyslogEntry{
		ReceivedAt: time.Now().UTC(),
		Facility:   1,
		Severity:   6,
		Hostname:   "unknown",
		AppName:    "-",
		ProcID:     "-",
		MsgID:      "-",
		SourceIP:   srcIP,
	}

	s := strings.TrimSpace(raw)

	// Parse priority <PRI>
	if len(s) > 3 && s[0] == '<' {
		end := strings.Index(s, ">")
		if end > 0 {
			entry.Facility, entry.Severity = parsePriority(s[1:end])
			s = s[end+1:]
		}
	}

	// Try RFC5424: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
	// Version is "1"
	if len(s) > 2 && s[0] == '1' && s[1] == ' ' {
		parts := strings.SplitN(s[2:], " ", 7)
		if len(parts) >= 6 {
			if h := parts[1]; h != "" && h != "-" {
				entry.Hostname = h
			} else {
				entry.Hostname = srcIP
			}
			if a := parts[2]; a != "-" {
				entry.AppName = a
			}
			entry.ProcID = parts[3]
			entry.MsgID = parts[4]
			// parts[5] is structured-data; actual message is parts[6] if present
			if len(parts) == 7 {
				entry.Message = parts[6]
			} else {
				entry.Message = parts[5]
			}
			return entry
		}
	}

	// RFC3164: Mmm DD HH:MM:SS HOSTNAME TAG: MSG
	// Skip timestamp (15 chars: "Jan  1 00:00:00")
	if len(s) >= 15 {
		rest := strings.TrimSpace(s[15:])
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx > 0 {
			entry.Hostname = rest[:spaceIdx]
			msg := strings.TrimSpace(rest[spaceIdx+1:])
			colonIdx := strings.Index(msg, ":")
			if colonIdx > 0 {
				tag := msg[:colonIdx]
				bracketIdx := strings.Index(tag, "[")
				if bracketIdx > 0 {
					entry.AppName = tag[:bracketIdx]
					entry.ProcID = strings.Trim(tag[bracketIdx:], "[]")
				} else {
					entry.AppName = tag
				}
				entry.Message = strings.TrimSpace(msg[colonIdx+1:])
			} else {
				entry.Message = msg
			}
		} else {
			// No hostname/tag structure — store the whole remainder as message
			log.Printf("WARN: RFC3164 parse fallback (no space) from %s: %.120s", srcIP, s)
			entry.Hostname = srcIP
			entry.Message = rest
		}
		return entry
	}

	// Unknown format — store raw so nothing is silently lost
	log.Printf("WARN: unrecognised syslog format from %s: %.120s", srcIP, raw)
	entry.Hostname = srcIP
	entry.Message = s
	return entry
}

type BatchWriter struct {
	mu      sync.Mutex
	conn    driver.Conn
	buffer  []SyslogEntry
	maxSize int
	ticker  *time.Ticker
	done    chan struct{}
}

func NewBatchWriter(conn driver.Conn, batchSize int, flushInterval time.Duration) *BatchWriter {
	bw := &BatchWriter{
		conn:    conn,
		buffer:  make([]SyslogEntry, 0, batchSize),
		maxSize: batchSize,
		ticker:  time.NewTicker(flushInterval),
		done:    make(chan struct{}),
	}
	go bw.flushLoop()
	return bw
}

func (bw *BatchWriter) Add(e SyslogEntry) {
	bw.mu.Lock()
	bw.buffer = append(bw.buffer, e)
	shouldFlush := len(bw.buffer) >= bw.maxSize
	bw.mu.Unlock()
	if shouldFlush {
		bw.Flush()
	}
}

func (bw *BatchWriter) flushLoop() {
	for {
		select {
		case <-bw.ticker.C:
			bw.Flush()
		case <-bw.done:
			bw.Flush()
			return
		}
	}
}

func (bw *BatchWriter) Flush() {
	bw.mu.Lock()
	if len(bw.buffer) == 0 {
		bw.mu.Unlock()
		return
	}
	batch := bw.buffer
	bw.buffer = make([]SyslogEntry, 0, bw.maxSize)
	bw.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := bw.conn.PrepareBatch(ctx, "INSERT INTO syslog.logs")
	if err != nil {
		log.Printf("prepare batch error: %v", err)
		return
	}

	for _, e := range batch {
		facilityName := "unknown"
		if int(e.Facility) < len(facilityNames) {
			facilityName = facilityNames[e.Facility]
		}
		severityName := "unknown"
		if int(e.Severity) < len(severityNames) {
			severityName = severityNames[e.Severity]
		}
		_ = b.Append(
			e.ReceivedAt,
			e.Facility,
			facilityName,
			e.Severity,
			severityName,
			e.Hostname,
			e.AppName,
			e.ProcID,
			e.MsgID,
			e.Message,
			e.SourceIP,
		)
	}

	if err := b.Send(); err != nil {
		log.Printf("batch send error: %v (dropped %d rows)", err, len(batch))
	} else {
		log.Printf("flushed %d log entries", len(batch))
	}
}

func (bw *BatchWriter) Stop() {
	bw.ticker.Stop()
	close(bw.done)
}

func connectClickHouse() driver.Conn {
	host := os.Getenv("CLICKHOUSE_HOST")
	if host == "" {
		host = "clickhouse"
	}
	addr := fmt.Sprintf("%s:9000", host)

	var conn driver.Conn
	var err error
	for i := 0; i < 30; i++ {
		conn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{addr},
			Auth: clickhouse.Auth{
				Database: "syslog",
				Username: "default",
				Password: "",
			},
			Settings: clickhouse.Settings{
				"max_execution_time": 60,
			},
			Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
			DialTimeout: 5 * time.Second,
		})
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = conn.Ping(ctx)
			cancel()
			if err == nil {
				log.Printf("connected to ClickHouse at %s", addr)
				return conn
			}
		}
		log.Printf("waiting for ClickHouse (%d/30): %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	log.Fatalf("could not connect to ClickHouse: %v", err)
	return nil
}

func main() {
	conn := connectClickHouse()
	defer conn.Close()

	bw := NewBatchWriter(conn, 1000, 2*time.Second)

	// UDP listener
	udpAddr, _ := net.ResolveUDPAddr("udp", ":514")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("UDP listen error: %v", err)
	}
	defer udpConn.Close()

	// TCP listener
	tcpLn, err := net.Listen("tcp", ":514")
	if err != nil {
		log.Fatalf("TCP listen error: %v", err)
	}
	defer tcpLn.Close()

	log.Println("syslog receiver listening on UDP/TCP :514")

	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			srcIP := addr.IP.String()
			entry := parseSyslog(string(buf[:n]), srcIP)
			bw.Add(entry)
		}
	}()

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go handleTCP(conn, bw)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down...")
	bw.Stop()
}

func handleTCP(conn net.Conn, bw *BatchWriter) {
	defer conn.Close()
	srcIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	buf := make([]byte, 65536)
	var accumulator strings.Builder
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		accumulator.Write(buf[:n])
		data := accumulator.String()
		for {
			idx := strings.Index(data, "\n")
			if idx < 0 {
				break
			}
			line := data[:idx]
			data = data[idx+1:]
			if line = strings.TrimSpace(line); line != "" {
				bw.Add(parseSyslog(line, srcIP))
			}
		}
		accumulator.Reset()
		accumulator.WriteString(data)
	}
}
