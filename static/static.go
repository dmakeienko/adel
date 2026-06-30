package static

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the embedded dist/ subtree rooted at "dist".
// Returns an error only if the embed layout is broken.
func FS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}

// Handler returns an http.Handler that serves the React SPA.
// All paths that don't match a real file fall back to index.html
// so that React Router's client-side routing works correctly.
func Handler() (http.Handler, error) {
	sub, err := FS()
	if err != nil {
		return nil, err
	}
	return &spaHandler{fs: http.FS(sub)}, nil
}

// spaHandler serves files from the embedded FS and falls back to
// index.html for any path that doesn't resolve to a real file,
// enabling React Router's HTML5 history API.
type spaHandler struct {
	fs http.FileSystem
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f, err := h.fs.Open(r.URL.Path)
	if err != nil {
		// Asset not found — serve index.html so React Router handles it.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		http.FileServer(h.fs).ServeHTTP(w, r2)
		return
	}
	f.Close()
	http.FileServer(h.fs).ServeHTTP(w, r)
}
