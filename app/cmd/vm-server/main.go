// Command vm-server runs a protected bytecode payload in "server mode": a warm,
// long-lived host that holds only the INERT encoded payload in memory and spins
// an EPHEMERAL mini-VM per request, executing it with request parameters and
// tearing it down. Requests are served in parallel, each in its own isolated VM.
//
// This is the runtime side of docs/DESIGN-vm-server-mode.md (the ephemeral mode):
//   - warm host  -> no per-request process spawn / decode-table rebuild cost
//   - ephemeral VM per request -> per-request secret window (decoded bytecode
//     lives only during the call, then is wiped) + clean state isolation
//
// The invariant: the host keeps the encoded blob + decode secrets, never the
// decoded program. Decoding happens inside bcrun.Run on every request.
//
// Honest framing (TECHNICAL §1.1, §8.2): this raises cost and keeps the secret
// window per-request; root on the host can still dump a decoded VM mid-request.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KamiGhost1/kamienclave/runtime/bcrun"
	"github.com/KamiGhost1/kamienclave/runtime/bytecode"
	"github.com/KamiGhost1/kamienclave/runtime/host"
)

type server struct {
	payload   []byte // inert, encoded; decoded per-request inside bcrun.Run
	seed      int64
	key       []byte
	maxSteps  int
	runTO     time.Duration
	logger    *log.Logger
	active    int64
	served    uint64
}

func main() {
	var (
		addr     = flag.String("addr", ":8099", "listen address")
		payloadF = flag.String("payload", "payload.bin", "encoded bytecode payload (factory output)")
		seed     = flag.Int64("opcode-seed", 0, "per-build opcode-table seed")
		keyB64   = flag.String("const-key", "", "per-build constant-pool key (base64, 32 bytes)")
		maxSteps = flag.Int("max-steps", 0, "VM step limit per request (0 = default)")
		runMS    = flag.Int("run-timeout-ms", 2000, "per-request execution timeout")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "vm-server ", log.LstdFlags|log.LUTC)

	payload, err := os.ReadFile(*payloadF)
	must(err, "read payload")
	key, err := base64.StdEncoding.DecodeString(*keyB64)
	must(err, "decode const-key")
	if len(key) != bytecode.ConstKeySize {
		logger.Fatalf("const-key wrong size: %d (want %d)", len(key), bytecode.ConstKeySize)
	}

	s := &server{
		payload: payload, seed: *seed, key: key,
		maxSteps: *maxSteps, runTO: time.Duration(*runMS) * time.Millisecond,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /stats", s.handleStats)
	mux.HandleFunc("POST /run", s.handleRun)

	logger.Printf("warm host up on %s (payload=%d bytes, ephemeral VM per request)", *addr, len(payload))
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	must(srv.ListenAndServe(), "serve")
}

type runReq struct {
	Env map[string]string `json:"env"` // request parameters, read via env.get("KEY")
}

type runResp struct {
	OK     bool     `json:"ok"`
	Result string   `json:"result"`           // Display() of the completion value
	Num    *float64 `json:"num,omitempty"`    // numeric value if applicable
	Logs   []string `json:"logs,omitempty"`   // captured log() output
	Error  string   `json:"error,omitempty"`
}

// handleRun executes the payload in a fresh, isolated VM for this request.
func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.active, 1)
	defer atomic.AddInt64(&s.active, -1)
	atomic.AddUint64(&s.served, 1)

	var req runReq
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, runResp{OK: false, Error: "decode: " + err.Error()})
			return
		}
	}

	// Fresh host bridge per request: request params in, captured logs out.
	var logbuf strings.Builder
	b := host.New()
	b.Log = host.WriterLogger{W: &logbuf}
	b.Env = req.Env

	ctx, cancel := context.WithTimeout(r.Context(), s.runTO)
	defer cancel()

	lim := bytecode.Limits{}
	if s.maxSteps > 0 {
		lim.MaxSteps = s.maxSteps
	}

	// bcrun.Run decodes the inert payload into a fresh VM, runs it, and wipes it.
	val, err := bcrun.Run(ctx, s.payload, s.seed, s.key, b, lim)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, runResp{OK: false, Error: err.Error(), Logs: splitLogs(logbuf.String())})
		return
	}
	resp := runResp{OK: true, Result: val.Display(), Logs: splitLogs(logbuf.String())}
	if n := val.Num(); !isNaN(n) {
		resp.Num = &n
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"active":       atomic.LoadInt64(&s.active),
		"served_total": atomic.LoadUint64(&s.served),
		"payload_size": len(s.payload),
		"mode":         "ephemeral",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func splitLogs(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func isNaN(f float64) bool { return f != f }

func must(err error, ctx string) {
	if err != nil {
		log.Fatalf("vm-server: %s: %v", ctx, err)
	}
}
