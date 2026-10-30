// tlsmux.go — one port, TLS for the API, a dead end for plaintext.
//
// api.listen stays on 18080 so bookmarks, nft rules and every script keep
// their address, but the socket now expects TLS. A connection whose first
// byte is not a TLS handshake record (0x16) is read as HTTP/1.x and answered
// without ever reaching the API mux:
//
//   - GET / HEAD → 308 to https://<host>/<same path>, so an old
//     http://node:18080/ui/ bookmark still lands on the console.
//   - anything else → 400 with a hint to switch to https. No redirect: a
//     request that carried a bearer token has already leaked it in the
//     clear, and bouncing it to https would hide that rather than fix it.
//
// Peeking happens per connection in its own goroutine with a short
// deadline, so a client that connects and sends nothing cannot stall
// Accept for everyone else.

package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// peekTimeout bounds how long a fresh connection may stay silent before it
// is dropped. Browsers and curl send the ClientHello immediately.
const peekTimeout = 5 * time.Second

// tlsMuxListener wraps a TCP listener. Accept returns only TLS-wrapped
// connections; plaintext ones are answered and closed internally.
type tlsMuxListener struct {
	net.Listener
	tlsConfig *tls.Config

	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
	err    error
	wg     sync.WaitGroup
}

func newTLSMuxListener(inner net.Listener, cfg *tls.Config) *tlsMuxListener {
	l := &tlsMuxListener{
		Listener:  inner,
		tlsConfig: cfg,
		conns:     make(chan net.Conn),
		closed:    make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *tlsMuxListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.err = err
			l.once.Do(func() { close(l.closed) })
			return
		}
		l.wg.Add(1)
		go l.dispatch(c)
	}
}

// dispatch classifies one connection by its first byte.
func (l *tlsMuxListener) dispatch(c net.Conn) {
	defer l.wg.Done()
	_ = c.SetReadDeadline(time.Now().Add(peekTimeout))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	bc := &bufferedConn{Conn: c, r: br}
	if first[0] == 0x16 {
		select {
		case l.conns <- tls.Server(bc, l.tlsConfig):
		case <-l.closed:
			c.Close()
		}
		return
	}
	answerPlaintext(bc, br)
}

func (l *tlsMuxListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

func (l *tlsMuxListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

// bufferedConn replays the peeked bytes before reading from the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// answerPlaintext parses one HTTP/1.x request off a non-TLS connection,
// writes the redirect or refusal, and closes it.
func answerPlaintext(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(peekTimeout))
	req, err := http.ReadRequest(br)
	if err != nil {
		writePlain(c, nil, http.StatusBadRequest, "this port speaks TLS; use https://\n")
		return
	}
	defer req.Body.Close()
	// Drain a small body so the client sees the response rather than a
	// reset; anything larger is not worth waiting for.
	_, _ = io.CopyN(io.Discard, req.Body, 4096)

	switch req.Method {
	case http.MethodGet, http.MethodHead:
		host := req.Host
		if host == "" {
			writePlain(c, req, http.StatusBadRequest, "this port speaks TLS; use https://\n")
			return
		}
		resp := &http.Response{
			StatusCode: http.StatusPermanentRedirect,
			ProtoMajor: 1, ProtoMinor: 1,
			Request: req,
			Header:  http.Header{"Location": {"https://" + host + req.URL.RequestURI()}, "Connection": {"close"}},
			Body:    http.NoBody,
		}
		_ = resp.Write(c)
	default:
		slog.Warn("api: plaintext request refused — rotate the token if this request carried one",
			"remote", c.RemoteAddr().String(), "method", req.Method, "path", req.URL.Path,
			"had_authorization", req.Header.Get("Authorization") != "")
		writePlain(c, req, http.StatusBadRequest,
			"this port speaks TLS; resend over https://. If this request carried an API token, rotate it: it has been sent in the clear.\n")
	}
}

func writePlain(c net.Conn, req *http.Request, status int, body string) {
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1, ProtoMinor: 1,
		Request:       req,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Connection": {"close"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	_ = resp.Write(c)
}

// serveTLS runs srv on addr behind the TLS mux until ctx ends.
func serveTLS(ctx context.Context, srv *http.Server, addr string, cfg *tls.Config) error {
	inner, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ln := newTLSMuxListener(inner, cfg)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		ln.Close()
	}()
	// Serve, not ServeTLS: the listener already hands out tls.Conns, and
	// ServeTLS would wrap them a second time.
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
