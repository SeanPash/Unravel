package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
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

	// AuthToken, when non-empty, is a shared bearer token required on every
	// route (HTTP and the /ws upgrade) via "Authorization: Bearer <token>" or
	// a "token" query parameter (the WebSocket browser API cannot set headers).
	AuthToken string

	// AllowEmptyOrigin permits WebSocket upgrades that carry no Origin header.
	// Only set this for loopback binds; a non-loopback listener should reject
	// origin-less requests to blunt cross-site WebSocket hijacking.
	AllowEmptyOrigin bool

	WriteTimeout time.Duration
	PingInterval time.Duration
}

// NewServer returns a Server with sensible defaults. Static may be nil during
// development when the React app is served by Vite on a separate port.
//
// opts apply after defaults so a caller can set AuthToken/AllowEmptyOrigin
// before CheckOrigin (which closes over the Server) is consulted.
func NewServer(bcast *Broadcaster, static fs.FS, opts ...func(*Server)) *Server {
	s := &Server{
		Bcast:            bcast,
		Static:           static,
		AllowEmptyOrigin: true,
		WriteTimeout:     5 * time.Second,
		PingInterval:     30 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.Upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// An absent Origin (non-browser client) is only trusted when
				// the listener is loopback-only.
				return s.AllowEmptyOrigin
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			h := u.Hostname()
			return h == "localhost" || h == "127.0.0.1"
		},
	}
	return s
}

// WithAuthToken sets the shared bearer token required on every route.
func WithAuthToken(token string) func(*Server) {
	return func(s *Server) { s.AuthToken = token }
}

// WithAllowEmptyOrigin controls whether origin-less WebSocket upgrades are
// accepted (true for loopback binds, false otherwise).
func WithAllowEmptyOrigin(allow bool) func(*Server) {
	return func(s *Server) { s.AllowEmptyOrigin = allow }
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
		mux.Handle("/", staticHandler(s.Static))
	}
	return s.withAuth(mux)
}

// entryAssetRe matches a Vite content-hashed bundle reference in index.html,
// e.g. /assets/index-DpJ0HMBp.js. The capture group is the asset type.
var entryAssetRe = regexp.MustCompile(`/assets/[A-Za-z0-9._-]+\.(js|css)`)

// currentEntryAssets reads the embedded index.html and returns the current
// bundle path for each asset type (js, css). The hashes change every build, so
// this is the single source of truth for what the live UI shell references.
func currentEntryAssets(fsys fs.FS) map[string]string {
	entries := map[string]string{}
	b, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return entries
	}
	for _, m := range entryAssetRe.FindAllStringSubmatch(string(b), -1) {
		if _, ok := entries[m[1]]; !ok {
			entries[m[1]] = m[0] // entries["js"] = "/assets/index-<hash>.js"
		}
	}
	return entries
}

// staticHandler serves the embedded UI with two protections against a rebuilt
// binary stranding a browser on a stale bundle (which renders as a black page).
//
// First, embedded files carry a zero modtime, so http.FileServer sends no
// Last-Modified or ETag; a browser can then heuristically hold a cached
// index.html that points at a content-hashed bundle the new binary no longer
// contains. index.html is therefore served no-store so the browser always
// re-fetches the current asset hashes.
//
// Second, no-store cannot evict an index.html a browser already cached before
// the fix shipped. So a missing /assets/*.{js,css} (a hash from an older build)
// is redirected to the current bundle of the same type rather than 404'd; the
// stale shell then loads the current script and recovers on an ordinary reload,
// with no manual hard refresh. Present hashed assets are immutable and cache
// indefinitely.
func staticHandler(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))
	entries := currentEntryAssets(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/assets/"):
			if _, err := fs.Stat(fsys, strings.TrimPrefix(p, "/")); err != nil {
				ext := strings.TrimPrefix(path.Ext(p), ".")
				if target, ok := entries[ext]; ok && target != p {
					w.Header().Set("Cache-Control", "no-store")
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			}
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		case p == "/" || p == "/index.html":
			w.Header().Set("Cache-Control", "no-store, must-revalidate")
		default:
			// Other top-level files (favicon, icons) revalidate cheaply.
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// withAuth wraps next so that, when AuthToken is set, every route except
// /healthz requires a matching bearer token. /healthz stays open so liveness
// probes and the startup connectivity check work without a credential.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.AuthToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || s.authorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// authorized reports whether r carries the configured bearer token, accepting
// either the Authorization header or a "token" query parameter (the browser
// WebSocket API cannot set request headers). Comparison is constant-time.
func (s *Server) authorized(r *http.Request) bool {
	if s.AuthToken == "" {
		return true
	}
	presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if presented == "" {
		presented = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.AuthToken)) == 1
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
