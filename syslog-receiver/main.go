package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
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

// skipStructuredData advances past the RFC5424 STRUCTURED-DATA field and
// returns the MSG portion. Handles nil ("-"), single, and multiple SD elements,
// including param-values that contain spaces.
func skipStructuredData(s string) string {
	if s == "" {
		return ""
	}
	// Nil structured data
	if s[0] == '-' {
		if len(s) > 2 {
			return s[2:] // skip "- "
		}
		return ""
	}
	if s[0] != '[' {
		return s
	}
	i := 0
	for i < len(s) && s[i] == '[' {
		inQuote := false
		i++ // skip '['
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && inQuote && i+1 < len(s) {
				i += 2 // skip escaped character
				continue
			}
			if c == '"' {
				inQuote = !inQuote
			} else if c == ']' && !inQuote {
				i++ // skip ']'
				closed = true
				break
			}
			i++
		}
		if !closed {
			break
		}
		if i < len(s) && s[i] == ' ' {
			i++ // skip space
			if i >= len(s) || s[i] != '[' {
				return s[i:] // space was MSG separator, not between SD elements
			}
			// Another SD element follows — continue the outer loop
		}
	}
	return s[i:]
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

	if len(s) > 3 && s[0] == '<' {
		end := strings.Index(s, ">")
		if end > 0 {
			entry.Facility, entry.Severity = parsePriority(s[1:end])
			s = s[end+1:]
		}
	}

	// RFC5424: 1 TIMESTAMP HOSTNAME APP-NAME PROCID [MSGID] STRUCTURED-DATA [MSG]
	// MSGID is technically required but many senders omit it.
	// Split into 6 so SD+MSG stay joined; handle both 5-field (no MSGID) and
	// 6-field forms, and detect when fields[4] is SD rather than MSGID.
	if len(s) >= 2 && s[0] == '1' && s[1] == ' ' {
		fields := strings.SplitN(s[2:], " ", 6)
		if len(fields) >= 5 {
			if h := fields[1]; h != "" && h != "-" {
				entry.Hostname = h
			} else {
				entry.Hostname = srcIP
			}
			if a := fields[2]; a != "-" {
				entry.AppName = a
			}
			entry.ProcID = fields[3]

			var sdAndMsg string
			if len(fields) == 6 {
				if strings.HasPrefix(fields[4], "[") {
					// Sender omitted MSGID; fields[4] is start of SD
					sdAndMsg = fields[4] + " " + fields[5]
				} else {
					entry.MsgID = fields[4]
					sdAndMsg = fields[5]
				}
			} else {
				// 5 fields: PROCID is the last, no SD or message
				sdAndMsg = fields[4]
			}
			entry.Message = skipStructuredData(sdAndMsg)
			return entry
		}
	}

	// RFC3164: Mmm DD HH:MM:SS [HOSTNAME] TAG: MSG
	// Hostname is optional on some devices — if the first token after the
	// timestamp looks like a tag (contains '[' or ends with ':'), skip it
	// and use srcIP instead.
	if len(s) >= 15 {
		rest := strings.TrimSpace(s[15:])
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx > 0 {
			candidate := rest[:spaceIdx]
			msg := strings.TrimSpace(rest[spaceIdx+1:])

			if looksLikeHostname(candidate) {
				entry.Hostname = candidate
			} else {
				// No hostname in this message — put candidate back into msg
				entry.Hostname = srcIP
				msg = rest
			}

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
			entry.Hostname = srcIP
			entry.Message = rest
		}
		return entry
	}

	log.Printf("WARN: unrecognised syslog format from %s: %.120s", srcIP, raw)
	entry.Hostname = srcIP
	entry.Message = s
	return entry
}

// ── Entry store (ring buffer with monotonic sequence numbers) ─────────────────
//
// The store is the source of truth for the poll endpoint. store.add() must be
// called before hub.broadcast() so that when a poll handler wakes up from the
// channel it always finds the entry already committed here.

type storedEntry struct {
	seq  uint64
	data json.RawMessage
}

type Store struct {
	mu      sync.Mutex
	entries []storedEntry
	nextSeq uint64
	maxSize int
}

func newStore(size int) *Store {
	return &Store{maxSize: size, entries: make([]storedEntry, 0, size)}
}

func (s *Store) add(data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, storedEntry{seq: s.nextSeq, data: json.RawMessage(data)})
	s.nextSeq++
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[len(s.entries)-s.maxSize:]
	}
}

// since returns all entries with seq >= afterSeq plus the current nextSeq.
func (s *Store) since(afterSeq uint64) ([]json.RawMessage, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]json.RawMessage, 0)
	for _, e := range s.entries {
		if e.seq >= afterSeq {
			out = append(out, e.data)
		}
	}
	return out, s.nextSeq
}

func (s *Store) currentSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSeq
}

// ── SSE hub (fan-out broadcast to connected clients) ─────────────────────────

type Hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

func newHub() *Hub { return &Hub{clients: make(map[chan string]struct{})} }

func (h *Hub) subscribe() chan string {
	ch := make(chan string, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan string) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *Hub) broadcast(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *Hub) streamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := h.subscribe()
	defer h.unsubscribe(ch)

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ── Long-poll handler ─────────────────────────────────────────────────────────
//
// GET /poll          → returns {seq, logs:[]} immediately (bootstrap cursor)
// GET /poll?seq=N    → blocks until entries with seq >= N exist, returns them
//
// Because store.add() is always called before hub.broadcast(), any entry that
// wakes this handler is already committed to the store. Re-reading the store
// after wakeup collects all entries that piled up in the same instant.

type pollResponse struct {
	Seq  uint64            `json:"seq"`
	Logs []json.RawMessage `json:"logs"`
}

func makePollHandler(hub *Hub, store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		seqStr := r.URL.Query().Get("seq")

		// Bootstrap: no cursor yet — return current seq so client can start from now.
		if seqStr == "" {
			json.NewEncoder(w).Encode(pollResponse{Seq: store.currentSeq(), Logs: []json.RawMessage{}})
			return
		}

		afterSeq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid seq", http.StatusBadRequest)
			return
		}

		// Fast path: entries already in the store.
		if entries, nextSeq := store.since(afterSeq); len(entries) > 0 {
			json.NewEncoder(w).Encode(pollResponse{Seq: nextSeq, Logs: entries})
			return
		}

		// Subscribe before the second check to close the race window.
		ch := hub.subscribe()
		defer hub.unsubscribe(ch)

		// Second check: an entry may have been stored between the first check
		// and subscribe().
		if entries, nextSeq := store.since(afterSeq); len(entries) > 0 {
			json.NewEncoder(w).Encode(pollResponse{Seq: nextSeq, Logs: entries})
			return
		}

		// Block until something arrives, client disconnects, or 30 s pass.
		timeout := time.NewTimer(30 * time.Second)
		defer timeout.Stop()

		select {
		case <-ch:
		case <-timeout.C:
		case <-r.Context().Done():
			return
		}

		// Drain any additional signals that piled up.
		for {
			select {
			case <-ch:
			default:
				goto respond
			}
		}
	respond:
		entries, nextSeq := store.since(afterSeq)
		json.NewEncoder(w).Encode(pollResponse{Seq: nextSeq, Logs: entries})
	}
}

// logEvent matches the JSON shape the frontend expects from ClickHouse queries.
type logEvent struct {
	ReceivedAt   string `json:"received_at"`
	Hostname     string `json:"hostname"`
	AppName      string `json:"app_name"`
	ProcID       string `json:"proc_id"`
	Severity     uint8  `json:"severity"`
	SeverityName string `json:"severity_name"`
	FacilityName string `json:"facility_name"`
	SourceIP     string `json:"source_ip"`
	Message      string `json:"message"`
}

func entryToJSON(e SyslogEntry) string {
	fn := "unknown"
	if int(e.Facility) < len(facilityNames) {
		fn = facilityNames[e.Facility]
	}
	sn := "unknown"
	if int(e.Severity) < len(severityNames) {
		sn = severityNames[e.Severity]
	}
	b, _ := json.Marshal(logEvent{
		ReceivedAt:   e.ReceivedAt.Format(time.RFC3339Nano),
		Hostname:     e.Hostname,
		AppName:      e.AppName,
		ProcID:       e.ProcID,
		Severity:     e.Severity,
		SeverityName: sn,
		FacilityName: fn,
		SourceIP:     e.SourceIP,
		Message:      e.Message,
	})
	return string(b)
}

// ── Batch writer ──────────────────────────────────────────────────────────────

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

// ── ClickHouse connection ─────────────────────────────────────────────────────

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

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	conn := connectClickHouse()
	defer conn.Close()

	bw := NewBatchWriter(conn, 1000, 2*time.Second)

	hub := newHub()
	store := newStore(10000)

	http.HandleFunc("/stream", hub.streamHandler)
	http.HandleFunc("/poll", makePollHandler(hub, store))
	go func() {
		log.Println("HTTP server listening on :8888")
		if err := http.ListenAndServe(":8888", nil); err != nil {
			log.Fatalf("HTTP server: %v", err)
		}
	}()

	listenUDP := func(network, addr string) {
		a, err := net.ResolveUDPAddr(network, addr)
		if err != nil {
			log.Printf("UDP resolve %s %s: %v", network, addr, err)
			return
		}
		conn, err := net.ListenUDP(network, a)
		if err != nil {
			log.Printf("UDP listen %s %s: %v (skipping)", network, addr, err)
			return
		}
		log.Printf("UDP listening on %s", conn.LocalAddr())
		go func() {
			defer conn.Close()
			buf := make([]byte, 65536)
			for {
				n, src, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				entry := parseSyslog(string(buf[:n]), normalizeIP(src.IP))
				msg := entryToJSON(entry)
				store.add(msg)
				hub.broadcast(msg)
				bw.Add(entry)
			}
		}()
	}

	listenTCP := func(network, addr string) {
		ln, err := net.Listen(network, addr)
		if err != nil {
			log.Printf("TCP listen %s %s: %v (skipping)", network, addr, err)
			return
		}
		log.Printf("TCP listening on %s", ln.Addr())
		go func() {
			defer ln.Close()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go handleTCP(conn, bw, hub, store)
			}
		}()
	}

	listenUDP("udp4", "0.0.0.0:514")
	listenUDP("udp6", "[::]:514")
	listenTCP("tcp4", "0.0.0.0:514")
	listenTCP("tcp6", "[::]:514")

	log.Println("syslog receiver listening on UDP/TCP :514 (IPv4 + IPv6)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down...")
	bw.Stop()
}

// looksLikeHostname returns true only for tokens that are plausibly a hostname
// or IP address in an RFC3164 message. Plain words (e.g. "HTTP", "Downloading")
// are rejected so embedded devices that omit the hostname field don't pollute
// the host column with log message content.
func looksLikeHostname(s string) bool {
	if s == "" || s == "-" {
		return false
	}
	// Structured-data fragments
	if strings.ContainsAny(s, "[]") {
		return false
	}
	// IP address (v4 or v6)
	if net.ParseIP(s) != nil {
		return true
	}
	// FQDN or hyphenated hostname (server-1, my.host.local)
	if strings.ContainsAny(s, ".-") {
		return true
	}
	// Hex string of 6+ chars: Docker short container IDs (ec6260604234),
	// MAC-derived device names, etc.
	if len(s) >= 6 {
		allHex := true
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	// Reject plain words — likely the start of a message from a device
	// that omits the hostname field.
	return false
}

// normalizeIP converts IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to plain IPv4.
func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func handleTCP(conn net.Conn, bw *BatchWriter, hub *Hub, store *Store) {
	defer conn.Close()
	srcIP := normalizeIP(conn.RemoteAddr().(*net.TCPAddr).IP)
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
				entry := parseSyslog(line, srcIP)
				msg := entryToJSON(entry)
				store.add(msg)
				hub.broadcast(msg)
				bw.Add(entry)
			}
		}
		accumulator.Reset()
		accumulator.WriteString(data)
	}
}
