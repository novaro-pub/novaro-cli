// Package listen is novaro listen's side of the relay: a WebSocket to
// GET /cli/listen in the account's test cell, whose events it POSTs to a
// local server, answering each with what that server said.
//
// The protocol, one JSON object per text message:
//
//	CLI   {"type":"listen","events":["payment.succeeded"],"api_version":"","device_name":""}
//	relay {"type":"ready","session_id":"cls_…","endpoint_id":"whe_…","secret":"whsec_…"}
//	relay {"type":"event","id":"<request>","headers":{…},"body":"<the delivery's body>"}
//	CLI   {"type":"result","id":"<request>","status":200,"duration_ms":12,"body":"…","error":""}
//	relay {"type":"error","code":"…","message":"…"}, then the socket closes
package listen

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// forwardWait is how long the local server has to answer: the delivery's
// own 10 s (the relay waits 15 s for the result). Tests shorten it.
var forwardWait = 10 * time.Second

// firstBackoff is the first wait before a new socket. Tests shorten it.
var firstBackoff = time.Second

const (
	// bodyLimit is how much of the answer goes back: the relay keeps 2 KB.
	bodyLimit = 2048
	// readyWait is how long the relay has to answer listen.
	readyWait = 20 * time.Second
	// maxBackoff bounds the wait between reconnects.
	maxBackoff = 30 * time.Second
)

// message is every message of the protocol.
type message struct {
	Type       string            `json:"type"`
	ID         string            `json:"id,omitempty"`
	Events     []string          `json:"events,omitempty"`
	APIVersion string            `json:"api_version,omitempty"`
	DeviceName string            `json:"device_name,omitempty"`
	Status     int               `json:"status,omitempty"`
	DurationMs int64             `json:"duration_ms,omitempty"`
	Body       string            `json:"body,omitempty"`
	Error      string            `json:"error,omitempty"`
	SessionID  string            `json:"session_id,omitempty"`
	EndpointID string            `json:"endpoint_id,omitempty"`
	Secret     string            `json:"secret,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Code       string            `json:"code,omitempty"`
	Message    string            `json:"message,omitempty"`
}

// Config is one novaro listen.
type Config struct {
	// URL is the socket's: ws(s)://api.<host>/cli/listen.
	URL        string
	Key        string
	UserAgent  string
	Events     []string
	APIVersion string
	DeviceName string
	// ForwardTo is the local server's URL; "" prints the events only.
	ForwardTo string
	// Headers are added to every forwarded request.
	Headers http.Header
	// SkipVerify accepts any certificate of an https ForwardTo.
	SkipVerify bool
	// Once stops after the ready message: --print-secret.
	Once bool
}

// Ready is what the relay said the session is.
type Ready struct {
	SessionID, EndpointID, Secret string
}

// Event is one event the relay sent, and what came of forwarding it.
type Event struct {
	At      time.Time
	ID      string // the event's evt_ id
	Type    string
	Body    []byte
	Result  Result
	Forward bool
}

// Result is the local server's answer, as the relay takes it.
type Result struct {
	Status   int
	Duration time.Duration
	Body     string
	// Error is "", timeout, connect or tls.
	Error string
	// Detail is the error's own text, for the terminal only.
	Detail string
}

// Output receives what listen shows.
type Output interface {
	Ready(Ready)
	Event(Event)
	Reconnecting(err error, wait time.Duration)
}

// Error is the relay's error message, or its refusal before the socket.
type Error struct {
	Code    string
	Message string
	Status  int // the HTTP status of a refused open
	// RetryAfter is the refusal's Retry-After.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Message + " (" + e.Code + ")"
}

// final says whether a new socket would end the same way: the CLI stops.
func (e *Error) final() bool {
	switch e.Code {
	case "server_stopping", "socket_failed", "socket_closed", "session_ended", "rate_limit", "temporarily_unavailable":
		return false
	}
	if e.Status == http.StatusTooManyRequests || e.Status >= 500 {
		return false
	}
	return true
}

// Run listens until ctx ends or the relay ends it for good. A dropped
// socket, a stopping pod or a stale session open a new one.
func Run(ctx context.Context, cfg Config, out Output) error {
	fwd := &http.Client{
		Timeout: forwardWait,
		// A redirect is the server's answer: the relay records 3xx.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipVerify}, //nolint:gosec // --skip-verify, the user's choice for a local server
		},
	}
	wait := firstBackoff
	for {
		readied, err := session(ctx, cfg, fwd, out)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil { // Once
			return nil
		}
		var e *Error
		if errors.As(err, &e) && e.final() {
			return err
		}
		if readied {
			wait = firstBackoff
		}
		if errors.As(err, &e) && e.RetryAfter > wait {
			wait = e.RetryAfter
		}
		out.Reconnecting(err, wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		wait = min(wait*2, maxBackoff)
	}
}

// session runs one socket; readied says whether the relay answered ready.
func session(ctx context.Context, cfg Config, fwd *http.Client, out Output) (readied bool, err error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+cfg.Key)
	if cfg.UserAgent != "" {
		h.Set("User-Agent", cfg.UserAgent)
	}
	dctx, cancel := context.WithTimeout(ctx, readyWait)
	defer cancel()
	// websocket.Dial closes the answer's body itself; a refusal's, which
	// refusal reads, is a copy in memory.
	conn, res, err := websocket.Dial(dctx, cfg.URL, &websocket.DialOptions{HTTPHeader: h}) //nolint:bodyclose // see above
	if err != nil {
		if res != nil {
			return false, refusal(res)
		}
		return false, fmt.Errorf("connect to %s: %w", cfg.URL, err)
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(1 << 20)

	if err := write(ctx, conn, message{Type: "listen", Events: cfg.Events, APIVersion: cfg.APIVersion, DeviceName: cfg.DeviceName}); err != nil {
		return false, err
	}
	m, err := read(dctx, conn)
	if err != nil {
		return false, err
	}
	switch m.Type {
	case "ready":
	case "error":
		return false, &Error{Code: m.Code, Message: m.Message}
	default:
		return false, fmt.Errorf("the relay answered %q before ready", m.Type)
	}
	out.Ready(Ready{SessionID: m.SessionID, EndpointID: m.EndpointID, Secret: m.Secret})
	if cfg.Once {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		return true, nil
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	for {
		m, err := read(sctx, conn)
		if err != nil {
			if ctx.Err() != nil {
				_ = conn.Close(websocket.StatusNormalClosure, "")
			}
			return true, err
		}
		switch m.Type {
		case "event":
			wg.Add(1)
			go func() {
				defer wg.Done()
				ev := forward(sctx, cfg, fwd, m)
				if err := write(sctx, conn, message{Type: "result", ID: m.ID, Status: ev.Result.Status,
					DurationMs: ev.Result.Duration.Milliseconds(), Body: ev.Result.Body, Error: ev.Result.Error}); err != nil {
					return
				}
				out.Event(ev)
			}()
		case "error":
			return true, &Error{Code: m.Code, Message: m.Message}
		}
	}
}

// forward POSTs one event to the local server.
func forward(ctx context.Context, cfg Config, c *http.Client, m message) Event {
	ev := Event{At: time.Now(), Body: []byte(m.Body), Forward: cfg.ForwardTo != ""}
	var head struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	_ = json.Unmarshal(ev.Body, &head)
	ev.ID, ev.Type = head.ID, head.Type
	if ev.ID == "" {
		ev.ID = m.Headers["PSP-Event-Id"]
	}
	if !ev.Forward {
		// Nothing to send it to: the event was seen, which is a 200.
		ev.Result = Result{Status: http.StatusOK}
		return ev
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ForwardTo, bytes.NewReader(ev.Body))
	if err != nil {
		ev.Result = Result{Error: "connect", Detail: err.Error()}
		return ev
	}
	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}
	for k, vs := range cfg.Headers {
		req.Header[http.CanonicalHeaderKey(k)] = vs
	}
	start := time.Now()
	res, err := c.Do(req)
	ev.Result.Duration = time.Since(start)
	if err != nil {
		ev.Result.Error, ev.Result.Detail = kind(err), err.Error()
		return ev
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, bodyLimit))
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	ev.Result.Status, ev.Result.Body = res.StatusCode, string(b)
	return ev
}

// kind is the relay's name for a failed POST.
func kind(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var cv *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	if errors.As(err, &cv) || errors.As(err, &rh) || strings.Contains(err.Error(), "tls:") {
		return "tls"
	}
	return "connect"
}

func write(ctx context.Context, c *websocket.Conn, m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(wctx, websocket.MessageText, b)
}

func read(ctx context.Context, c *websocket.Conn) (message, error) {
	for {
		typ, b, err := c.Read(ctx)
		if err != nil {
			return message{}, closed(err)
		}
		if typ != websocket.MessageText {
			continue
		}
		var m message
		if err := json.Unmarshal(b, &m); err != nil {
			return message{}, fmt.Errorf("the relay sent what is not a message: %w", err)
		}
		return m, nil
	}
}

// closed names a socket's close by its reason, which the relay sets to the
// error's code. One closed with no reason (a load balancer's, a pod gone)
// is socket_closed, and a new socket follows.
func closed(err error) error {
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		code := ce.Reason
		if code == "" {
			code = "socket_closed"
		}
		return &Error{Code: code, Message: "the relay closed the socket (" + ce.Code.String() + ")"}
	}
	return err
}

// refusal reads a refused open: the API's JSON error, or the status.
func refusal(res *http.Response) error {
	e := &Error{Status: res.StatusCode, Message: res.Status}
	if res.Body != nil {
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		if json.Unmarshal(b, &env) == nil && env.Error.Message != "" {
			e.Code, e.Message = env.Error.Code, env.Error.Message
		}
	}
	if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
		e.RetryAfter = time.Duration(s) * time.Second
	}
	return e
}

// SocketURL is the socket's URL on the API's address.
func SocketURL(apiBase string) (string, error) {
	u, err := url.Parse(apiBase)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("the API's address %q is not http(s)", apiBase)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/cli/listen"
	return u.String(), nil
}
