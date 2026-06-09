package api

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// Server hosts the HTTP+WebSocket endpoints the UI consumes. Static is the
// React production build served at "/"; the WebSocket handler lives at "/ws"
// and registers each client with the shared Broadcaster.
type Server struct {
	Bcast    *Broadcaster
	Static   fs.FS
	Upgrader websocket.Upgrader

	WriteTimeout time.Duration
	PingInterval time.Duration
}

// NewServer returns a Server with sensible defaults. Static may be nil during
// development when the React app is served by Vite on a separate port.
func NewServer(bcast *Broadcaster, static fs.FS) *Server {
	return &Server{
		Bcast:  bcast,
		Static: static,
		Upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true
				}
				u, err := url.Parse(origin)
				if err != nil {
					return false
				}
				h := u.Hostname()
				return h == "localhost" || h == "127.0.0.1"
			},
		},
		WriteTimeout: 5 * time.Second,
		PingInterval: 30 * time.Second,
	}
}

// Handler builds the http.Handler tree. Returned separately from ListenAndServe
// so tests can wrap it in httptest.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.serveWS)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	if s.Static != nil {
		mux.Handle("/", http.FileServer(http.FS(s.Static)))
	}
	return mux
}

// ListenAndServe blocks until ctx is canceled or the server errors out.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already written a response.
		return
	}
	sub := s.Bcast.Subscribe()
	defer sub.Unsubscribe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// We don't expect client -> server messages; reading drains pings and
		// notifies us when the client disconnects.
		conn.SetReadLimit(1 << 20)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(s.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				return
			}
			if err := writeJSON(conn, msg, s.WriteTimeout); err != nil {
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func writeJSON(conn *websocket.Conn, msg types.WSMessage, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return conn.WriteJSON(msg)
}

// WSURL is a tiny helper for tests: rewrites an http:// httptest URL into the
// ws:// form the gorilla client expects.
func WSURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http") + "/ws"
}
